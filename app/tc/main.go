package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

/* 下面是 C 代码 */

/*
#include <limit.c>
*/
// import "C"

func init() {
	err := rlimit.RemoveMemlock()
	fmt.Printf("remove mem lock: %v", err)
	// cur := C.cur()
	// m := C.max()
	// set := C.set()
	// fmt.Printf("cur: %d, max: %d, set: %d", cur, m, set)
}

func main() {
	// open a rtnetlink socket
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// get all the qdiscs from all interfaces
	qdiscs, err := rtnl.Qdisc().Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get qdiscs: %v\n", err)
		return
	}

	rtnl.Qdisc().Add(&tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(10),
			Handle:  core.BuildHandle(0, 0x0000),
			Parent:  tc.HandleIngress,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	})

	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get interface from id %d: %v", qdisc.Ifindex, err)
			return
		}
		fmt.Printf("%20s\t%s\n", iface.Name, qdisc.Kind)
	}

	rtnl.Filter().MonitorWithErrorFunc(context.Background(), time.Hour, func(action uint16, m tc.Object) int {
		fmt.Printf("get attached %d: %+v\n", action, m)
		fmt.Printf("bpf: %+v\n", m.BPF)
		return 0
	}, func(e error) int {
		return 0
	})
	coll, err := ebpf.LoadCollectionSpec("bpf/mb_tc.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load collection from file: %v\n", err)
		return
	}
	fmt.Printf("call: %v\n", coll.Programs)
	// for k, v := range coll.Maps {
	// 	fmt.Printf("map: %s: %+v\n", k, *v)
	// }
	type kebe struct {
		Foo *ebpf.Program `ebpf:"mb_tc_ingress"`
		// LPI *ebpf.Map `ebpf:"local_pod_ips"`
		// Bar     *ebpf.Map     `ebpf:"pair_original_dst"`
		Ignored int
	}
	mm, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/local_pod_ips", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Printf("load map err: %v", err)
	}
	err = coll.RewriteMaps(map[string]*ebpf.Map{
		"local_pod_ips": mm,
	})
	if err != nil {
		fmt.Printf("rewrite map err: %v", err)
	}
	k := kebe{}
	// coll.RewriteMaps()
	err = coll.LoadAndAssign(&k, &ebpf.CollectionOptions{})
	if err != nil {
		fmt.Printf("load and assgin error: %v", err)
		return
	}

	fmt.Printf("kebe %+v\n", k)
	// ms := map[string]*ebpf.Map{}
	// for s, m := range coll.Maps {
	// 	m, err := ebpf.NewMapWithOptions(m, ebpf.MapOptions{})
	// 	fmt.Printf("load map %s error: %v\n", s, err)
	// 	ms[s] = m
	// }
	// fmt.Printf("maps: %+v\n", ms)
	// ebpf.NewProgram()
	// ing, err := ebpf.NewProgramWithOptions(coll.Programs["mb_tc_ingress"],
	// 	ebpf.ProgramOptions{
	// 		LogLevel: 1,
	// 		LogSize:  65536,
	// 	})
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
	// 	return
	// }
	// defer ing.Close()
	ing := k.Foo
	info, _ := ing.Info()
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(10),
			// Handle:  0,
			Parent: 0xFFFFFFF2,
			Info: core.BuildHandle(
				66,     // prio
				0x0300, // protocol
			),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(ing.FD())),
				Name:  stringPtr(info.Name),
				Flags: uint32Ptr(0x1),
			},
			Prio: &tc.Prio{Bands: 66},
		},
	}
	if err := rtnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}
	fmt.Printf("successfully load tc\n")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
	<-ch
	rtnl.Filter().Delete(&filter)
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}
