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
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"istio.io/istio/cni/pkg/plugin"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/pkg/linux"
)

func netnsPairEthDo(nsname string, f func(name string, index int) error) error {
	netNS, err := ns.GetNS(nsname)
	if err != nil {
		return err
	}
	pairIndexes := []int{}
	err = netNS.Do(func(_ ns.NetNS) error {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Name == "lo" {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			buf := new(bytes.Buffer)
			c := exec.Command("sh", "-c", fmt.Sprintf("ip link show %s | awk 'NR<2{print $2}' | tr ':' ' ' | awk -F '@if' '{print $2}'", iface.Name))
			c.Stdout = buf
			if err := c.Run(); err != nil {
				return fmt.Errorf("not get pair ifindex: %v", err)
			}
			pairIndex, err := strconv.Atoi(strings.TrimSpace(buf.String()))
			if err != nil {
				return fmt.Errorf("not get pair ifindex: %v", err)
			}
			pairIndexes = append(pairIndexes, pairIndex)
			err = f(iface.Name, iface.Index)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	ifaces, _ := net.Interfaces()
	find := false
	for _, iface := range ifaces {
		for _, index := range pairIndexes {
			if iface.Index == index {
				find = true
				err = f(iface.Name, iface.Index)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	if !find {
		return fmt.Errorf("merbridge requires pair eth for pod's eth")
	}
	return nil
}

func getXDPPinnedPath(bpfPath, ns, pod, eth string) string {
	return path.Join(bpfPath, "xdps", ns, pod, eth)
}

func getMarkKeyOfNetns(netns string) uint32 {
	// todo check confict?
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
	netNS, err := ns.GetNS("/host" + args.Netns)
	if err != nil {
		log.Errorf("get ns %s error", args.Netns)
		return err
	}
	err = netNS.Do(func(_ ns.NetNS) error {
		// listen on 39807
		return s.buildListener(netNS.Path())
	})
	if err != nil {
		log.Errorf("Failed to build listener for %s: %v", args.Netns, err)
		return err
	}
	// attach xdp to the veth pair
	err = netnsPairEthDo(netNS.Path(), func(name string, index int) error {
		xdp, err := ebpf.LoadPinnedProgram(path.Join(s.bpfMountPath, "mb_xdp"), &ebpf.LoadPinOptions{})
		// todo support load by ID: xdp, err := ebpf.NewProgramFromID(1595)
		if err != nil {
			log.Errorf("Failed to load %s: %v", path.Join(s.bpfMountPath, "mb_xdp"), err)
			return err
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   xdp,
			Interface: index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Errorf("Failed to attach xdp to interface (index: %d): %v", index, err)
			return err
		}
		p := getXDPPinnedPath(s.bpfMountPath, string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME), name)
		_ = os.MkdirAll(p, os.ModePerm)
		return l.Pin(path.Join(p, "mb_xdp"))
	})
	return err
}

func (s *server) CmdDelete(args *skel.CmdArgs) (err error) {
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}
	p := path.Join(s.bpfMountPath, "xdps", string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME))
	os.RemoveAll(p)
	m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "mark_pod_ips_map"), &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}
	key := getMarkKeyOfNetns(args.Netns)
	return m.Delete(key)
}

// listen on 39807
func (s *server) buildListener(netns string) error {
	addrs := []net.Addr{}
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
				var key uint32 = getMarkKeyOfNetns(netns)
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
				// ignore uninjected pods
				log.Debugf("skip listening for pid(%s)", pid)
				continue
			}
			if err = netns.Do(func(_ ns.NetNS) error {
				log.Infof("build listener for pid(%s)", pid)
				// listen on 39807
				return s.buildListener(netns.Path())
			}); err != nil {
				if errors.Is(err, syscall.EADDRINUSE) {
					// skip if it has listened on 39807
					continue
				}
				return err
			}
			// attach xdp to the veth pair
			if err = netnsPairEthDo(netns.Path(), func(name string, index int) error {
				xdp, err := ebpf.LoadPinnedProgram(path.Join(s.bpfMountPath, "mb_xdp"), &ebpf.LoadPinOptions{})
				// todo support load by ID: xdp, err := ebpf.NewProgramFromID(1595)
				if err != nil {
					log.Errorf("Failed to load %s: %v", path.Join(s.bpfMountPath, "mb_xdp"), err)
					return err
				}

				l, err := link.AttachXDP(link.XDPOptions{
					Program:   xdp,
					Interface: index,
					Flags:     link.XDPGenericMode,
				})
				if err != nil {
					log.Errorf("Failed to attach xdp to interface (index: %d): %v", index, err)
					return err
				}
				p := getXDPPinnedPath(s.bpfMountPath, pid, pid, name)
				_ = os.MkdirAll(p, os.ModePerm)
				return l.Pin(path.Join(p, "mb_xdp"))
			}); err != nil {
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
