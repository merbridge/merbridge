/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cniserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"istio.io/istio/cni/pkg/plugin"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/pkg/linux"
)

type qdisc struct {
	device    string
	hasClsact bool
}

func getMarkKeyOfNetns(netns string) uint32 {
	// todo check conflict?
	algorithm := fnv.New32a()
	_, _ = algorithm.Write([]byte(netns))
	return algorithm.Sum32()
}

func (s *server) CmdAdd(args *skel.CmdArgs) (err error) {
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("merbridge-cni panicked during cmdAdd: %v\n%v", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: %v", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			log.Errorf("merbridge-cni cmdAdd error: %v", err)
		}
	}()
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}
	netns, err := ns.GetNS("/host" + args.Netns)
	if err != nil {
		log.Errorf("get ns %s error", args.Netns)
		return err
	}
	err = netns.Do(func(_ ns.NetNS) error {
		// listen on 39807
		if err := s.buildListener(netns.Path()); err != nil {
			return err
		}
		// attach tc to the device
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Name != "lo" {
				return s.attachTC(netns.Path(), iface.Name)
			}
		}
		return fmt.Errorf("device not found for %s", args.Netns)
	})
	if err != nil {
		log.Errorf("CmdAdd failed for %s: %v", args.Netns, err)
		return err
	}
	return err
}

func (s *server) CmdDelete(args *skel.CmdArgs) (err error) {
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}
	s.Lock()
	delete(s.qdiscs, "/host"+args.Netns)
	s.Unlock()
	m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "mark_pod_ips_map"), &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}
	key := getMarkKeyOfNetns(args.Netns)
	return m.Delete(key)
}

// listen on 39807
func (s *server) buildListener(netns string) error {
	var addrs []net.Addr
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil || len(ifAddrs) == 0 {
			continue
		}
		addrs = append(addrs, ifAddrs...)
	}
	if len(addrs) == 0 {
		log.Errorf("no ip address for %s", netns)
		return nil
	}
	if len(addrs) != 1 {
		log.Warnf("get ip address for %s: res: %v, merbridge only support single ip address", netns, addrs)
	}
	lc := s.listenConfig(addrs[0], netns)
	l, err := lc.Listen(context.Background(), "tcp", "0.0.0.0:39807")
	if err != nil {
		return err
	}
	go func() {
		// keep listener
		for {
			_, err := l.Accept()
			if err != nil {
				// only break loop if error.
				break
			}
		}
	}()
	return nil
}

func (s *server) listenConfig(addr net.Addr, netns string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "mark_pod_ips_map"), &ebpf.LoadPinOptions{})
				if err != nil {
					operr = err
					return
				}
				var ip uint32
				switch v := addr.(type) { // todo instead of hash
				case *net.IPNet: // nolint: typecheck
					ip, err = linux.IP2Linux(v.IP.String())
				case *net.IPAddr: // nolint: typecheck
					ip, err = linux.IP2Linux(v.String())
				}
				if err != nil {
					operr = err
					return
				}
				key := getMarkKeyOfNetns(netns)
				operr = m.Update(key, ip, ebpf.UpdateAny)
				if operr != nil {
					return
				}
				operr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(key))
			}); err != nil {
				return err
			}
			return operr
		},
	}
}

func (s *server) checkAndRepairPodPrograms() error {
	hostProc, err := os.ReadDir(config.HostProc)
	if err != nil {
		return err
	}
	for _, f := range hostProc {
		if _, err = strconv.Atoi(f.Name()); err == nil {
			pid := f.Name()
			np := fmt.Sprintf("%s/%s/ns/net", config.HostProc, pid)
			netns, err := ns.GetNS(np)
			if err != nil {
				log.Errorf("Failed to get ns for %s, error: %v", np, err)
				continue
			}
			if skipListening(pid) {
				// ignore non-injected pods
				log.Debugf("skip listening for pid(%s)", pid)
				continue
			}
			if err = netns.Do(func(_ ns.NetNS) error {
				log.Infof("build listener for pid(%s)", pid)
				// listen on 39807
				if err := s.buildListener(netns.Path()); err != nil {
					return err
				}
				// attach tc to the device
				ifaces, _ := net.Interfaces()
				for _, iface := range ifaces {
					if iface.Name != "lo" {
						return s.attachTC(netns.Path(), iface.Name)
					}
				}
				return fmt.Errorf("device not found for pid(%s)", pid)
			}); err != nil {
				if errors.Is(err, syscall.EADDRINUSE) {
					// skip if it has listened on 39807
					continue
				}
				return err
			}
		}
	}
	return nil
}

func skipListening(pid string) bool {
	b, _ := os.ReadFile(fmt.Sprintf("%s/%s/comm", config.HostProc, pid))
	comm := string(b)
	if strings.TrimSpace(comm) != "pilot-agent" {
		return true
	}

	findStr := func(path string, str []byte) bool {
		f, _ := os.Open(path)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Split(bufio.ScanLines)
		for sc.Scan() {
			if bytes.Contains(sc.Bytes(), str) {
				return true
			}
		}
		return false
	}

	conn4 := fmt.Sprintf("%s/%s/net/tcp", config.HostProc, pid)
	return !findStr(conn4, []byte(fmt.Sprintf(": %0.8d:%0.4X %0.8d:%0.4X 0A", 0, 15001, 0, 0)))
}

func (s *server) attachTC(netns, dev string) error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("tc qdisc add dev %s clsact", dev))
	err := cmd.Run()
	hasCls := false
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		log.Errorf("Add clsact to %s failed: unexpected exit code: %d, err: %v", dev, code, err)
		// TODO(dddddai): check if clsact exists
		hasCls = true
	}

	obj := "bpf/mb_tc.o"

	cmd = exec.Command("sh", "-c", fmt.Sprintf("tc filter add prio 66 dev %s ingress bpf da obj %s sec classifier_ingress", dev, obj))
	err = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("failed to attach tc(ingress) to %s, unexpected exit code: %d, err: %v", dev, code, err)
	}
	cmd = exec.Command("sh", "-c", fmt.Sprintf("tc filter add prio 66 dev %s egress bpf da obj %s sec classifier_egress", dev, obj))
	err = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("failed to attach tc(egress) to %s, unexpected exit code: %d, err: %v", dev, code, err)
	}
	s.Lock()
	s.qdiscs[netns] = qdisc{
		device:    dev,
		hasClsact: hasCls,
	}
	s.Unlock()
	return nil
}

func (s *server) cleanUpTC() {
	s.Lock()
	defer s.Unlock()
	for nn, q := range s.qdiscs {
		netns, err := ns.GetNS(nn)
		if err != nil {
			log.Errorf("Failed to get ns for %s, error: %v", nn, err)
			continue
		}
		if err = netns.Do(func(_ ns.NetNS) error {
			if !q.hasClsact {
				cmd := exec.Command("sh", "-c", fmt.Sprintf("tc qdisc delete dev %s clsact", q.device))
				err := cmd.Run()
				if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
					return fmt.Errorf("failed to delete clsact from %s, unexpected exit code: %d, err: %v", q.device, code, err)
				}
			} else {
				cmd := exec.Command("sh", "-c", fmt.Sprintf("tc filter delete dev %s egress prio 66", q.device))
				err := cmd.Run()
				if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
					return fmt.Errorf("failed to delete egress filter from %s, unexpected exit code: %d, err: %v", q.device, code, err)
				}
				cmd = exec.Command("sh", "-c", fmt.Sprintf("tc filter delete dev %s ingress prio 66", q.device))
				err = cmd.Run()
				if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
					return fmt.Errorf("failed to delete ingress filter from %s, unexpected exit code: %d, err: %v", q.device, code, err)
				}
			}
			return nil
		}); err != nil {
			log.Errorf("Failed to clean up tc for %s, error: %v", nn, err)
		}
	}
}
