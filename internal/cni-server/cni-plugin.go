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
	"bytes"
	"context"
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

	"github.com/merbridge/merbridge/pkg/linux"
)

func netnsEthsGetIPs(nsname string) []net.Addr {
	outAddrs := []net.Addr{}
	netNS, err := ns.GetNS(nsname)
	if err != nil {
		log.Errorf("get ns %s error", nsname)
		return outAddrs
	}
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
			outAddrs = append(outAddrs, addrs...)
		}
		return nil
	})
	if err != nil {
		log.Errorf("get netns %s ip addresses error: %v", nsname, err)
	}
	return outAddrs
}

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

			buf := bytes.NewBuffer(nil)
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
	addrs := netnsEthsGetIPs(args.Netns)
	if len(addrs) != 1 {
		return fmt.Errorf("get ip address of %s error: res: %v, merbridge only support single ip address", args.Netns, addrs)
	}
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "mark_pod_ips_map"), &ebpf.LoadPinOptions{})
				if err != nil {
					operr = err
					return
				}
				var ip uint32
				switch v := addrs[0].(type) { // todo instead of hash
				case *net.IPNet: // nolint: typecheck
					ip, err = linux.IP2Linux(v.IP.String())
				case *net.IPAddr: // nolint: typecheck
					ip, err = linux.IP2Linux(v.String())
				}
				if err != nil {
					operr = err
					return
				}
				var key uint32 = getMarkKeyOfNetns(args.Netns)
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
	netNS, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Errorf("get ns %s error", args.Netns)
		return err
	}
	err = netNS.Do(func(nn ns.NetNS) error {
		l, err := lc.Listen(context.Background(), "tcp", "0.0.0.0:39807")
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
		return err
	})
	if err != nil {
		return err
	}
	err = netnsPairEthDo(args.Netns, func(name string, index int) error {
		xdp, err := ebpf.LoadPinnedProgram(path.Join(s.bpfMountPath, "mb_xdp"), &ebpf.LoadPinOptions{})
		// todo support load by ID: xdp, err := ebpf.NewProgramFromID(1595)
		if err != nil {
			return err
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   xdp,
			Interface: index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
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
