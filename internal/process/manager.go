package process

import (
	"fmt"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	processwatcher "github.com/merbridge/process-watcher"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/pkg/linux"
)

const (
	AMBIENT_MESH_MODE_FLAG = (1 << 0)
	ZTUNNEL_FLAG           = (1 << 2)
	ZTUNNEL_IP_KEY         = 0x1
)

type cgroupInfo struct {
	// sync from bpf/headers/helpers.h cgroup_info
	/*
			__u64 id;
		    __u32 is_in_mesh;
		    __u32 cgroup_ip[4];
		    // We can't specify which ports are listened to here, so we open up a flags,
		    // user-defined. E.g, for those who wish to determine if port 15001 is
		    // listened to, we can customize a flag, `IS_LISTEN_15001 = 1 << 2`, which
		    // we can subsequently detect by `flags & IS_LISTEN_15001`.
		    __u16 flags;
		    // detected_flags is used to determine if this operation has ever been
		    // performed. if `flags & IS_LISTEN_15001` is false but `detected_flags &
		    // IS_LISTEN_15001` is true, that means real true, we do not need recheck.
		    // but if `detected_flags & IS_LISTEN_15001` is false, that probably means
		    // we haven't tested it and need to retest it.
		    __u16 detected_flags;
	*/
	ID            uint64
	IsInMesh      uint32
	CgroupIp      [4]uint32
	Flags         uint16
	DetectedFlags uint16
}

type ProcessManager interface {
	Run(stop chan struct{}) error
	OnPodStatusChanged(ip string, isInMesh bool, isAmbient bool, isZtunnel bool) error
}

type podInfo struct {
	ip        string
	isInMesh  bool
	isAmbient bool
	isZtunnel bool
}

type processManager struct {
	lock            sync.RWMutex
	processWatcher  processwatcher.Watcher
	cgroupMountPath string
	pidCgroupMap    map[uint32]uint64
	cgroupIPMap     map[uint64]string
	ipCgroupsMap    map[string]map[uint64]bool
	podIPModeMap    map[string]podInfo
}

func NewProcessManager(cgroupMountPath string) (ProcessManager, error) {
	if cgroupMountPath == "" {
		p, err := linux.GetCgroup2MountPath(config.HostProc)
		if err != nil {
			return nil, err
		}
		if p == "" {
			// try cgroupv1
			p, err = linux.GetCgroupSystemdMountPath(config.HostProc)
			if err != nil {
				return nil, err
			}
			if p == "" {
				return nil, fmt.Errorf("can not fetch cgroup mount path")
			}
		}
		cgroupMountPath = p
	}
	return &processManager{
		processWatcher:  processwatcher.NewProcessWatcher(),
		cgroupMountPath: cgroupMountPath,
		pidCgroupMap:    make(map[uint32]uint64),
		cgroupIPMap:     make(map[uint64]string),
		ipCgroupsMap:    make(map[string]map[uint64]bool),
		podIPModeMap:    make(map[string]podInfo),
	}, nil
}

// if process's ips more than 1 v4 or 1 v6, we dont deal with it
// it may be hostnetwork pod
func isSupportedPodProcess(ips []net.Addr) bool {
	if len(ips) > 2 {
		return false
	}
	ipv4 := 0
	for _, ip := range ips {
		if !strings.Contains(ip.String(), ":") {
			ipv4 += 1
		}
	}
	return ipv4 == 1
}

func isInKube(cgroup string) bool {
	return strings.Contains(cgroup, "kubepods")
}

func getProcessCgroup(pid uint32) (string, error) {
	cgr, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", config.HostProc, pid))
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(cgr)), "\n")
	cgline := lines[len(lines)-1]
	cg := strings.Split(cgline, ":")
	if len(cg) < 3 {
		return "", fmt.Errorf("error cgroup found: %s", cgline)
	}
	return strings.Join(cg[2:], ":"), nil
}

func getProcessIps(pid uint32) ([]net.Addr, error) {
	netpath := fmt.Sprintf("%s/%d/ns/net", config.HostProc, pid)
	netns, err := ns.GetNS(netpath)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.Addr, 0)
	err = netns.Do(func(nn ns.NetNS) error {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if strings.Contains(iface.Name, "istio") {
				continue
			}
			if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
				as, err := iface.Addrs()
				if err != nil {
					return err
				}
				addrs = append(addrs, as...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// pureIP will clean up cidr suffix
func pureIP(addr string) string {
	return strings.Split(addr, "/")[0]
}

func getIPKey(ips []net.Addr) string {
	if len(ips) == 1 {
		return pureIP(ips[0].String())
	}
	for _, ip := range ips {
		if !strings.Contains(ip.String(), ":") {
			// ipv4
			return pureIP(ip.String())
		}
	}
	return ""
}

func (w *processManager) writePodInfoToCgroupMap(cgroupInode uint64, pod podInfo) error {
	cgrinfo := cgroupInfo{}
	if err := ebpfs.GetCgroupInfoMap().Lookup(&cgroupInode, &cgrinfo); err != nil {
		log.Debugf("lookup cgroup info for %d error: %v", cgroupInode, err)
	}
	var in uint32
	if pod.isInMesh {
		in = 1
	}
	_ip, _ := linux.IP2Linux(pod.ip)
	flag := cgrinfo.Flags
	if pod.isAmbient {
		flag |= AMBIENT_MESH_MODE_FLAG
	} else {
		flag &= ^uint16(AMBIENT_MESH_MODE_FLAG)
	}
	if pod.isZtunnel {
		flag |= ZTUNNEL_FLAG
	} else {
		flag &= ^uint16(ZTUNNEL_FLAG)
	}
	tcg := cgroupInfo{
		ID:            cgroupInode,
		IsInMesh:      in,
		CgroupIp:      *(*[4]uint32)(_ip),
		Flags:         flag,
		DetectedFlags: cgrinfo.DetectedFlags | AMBIENT_MESH_MODE_FLAG | ZTUNNEL_FLAG,
	}
	if reflect.DeepEqual(tcg, cgrinfo) {
		return nil
	}
	return ebpfs.GetCgroupInfoMap().Update(&cgroupInode, &tcg, ebpf.UpdateAny)
}

func (w *processManager) onProcessAdded(pid uint32) error {
	cgroup, err := getProcessCgroup(pid)
	if err != nil {
		log.Errorf("get process %d cgroup error: %v", pid, err)
		return err
	}
	if !isInKube(cgroup) {
		// process is not running in kubernetes
		return nil
	}
	cgroupInode, err := linux.GetFileInode(path.Join(w.cgroupMountPath, cgroup))
	if err != nil {
		return err
	}
	w.lock.RLock()
	ipkey := w.cgroupIPMap[cgroupInode]
	w.lock.RUnlock()
	zeroip := "0.0.0.0"
	if ipkey == "" {
		ips, err := getProcessIps(pid)
		if err != nil {
			return err
		}
		if !isSupportedPodProcess(ips) {
			log.Debugf("process %d is a container process, but we not supported", pid)
			w.lock.Lock()
			defer w.lock.Unlock()
			w.cgroupIPMap[cgroupInode] = zeroip
			return nil
		}
		ipkey = getIPKey(ips)
	} else if ipkey == zeroip {
		// only for cache
		return nil
	}
	w.lock.Lock()
	defer w.lock.Unlock()

	w.pidCgroupMap[pid] = cgroupInode
	w.cgroupIPMap[cgroupInode] = ipkey
	if _, ok := w.ipCgroupsMap[ipkey]; !ok {
		w.ipCgroupsMap[ipkey] = make(map[uint64]bool)
	}
	w.ipCgroupsMap[ipkey][cgroupInode] = true
	if _, ok := w.podIPModeMap[ipkey]; !ok {
		w.podIPModeMap[ipkey] = podInfo{
			ip: ipkey,
		}
	}

	return w.writePodInfoToCgroupMap(cgroupInode, w.podIPModeMap[ipkey])
}

func (w *processManager) onProcessExit(pid uint32) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	cgroupInode, ok := w.pidCgroupMap[pid]
	if !ok {
		return nil
	}
	delete(w.pidCgroupMap, pid) // delete for map
	find := false
	for _, cg := range w.pidCgroupMap {
		if cgroupInode == cg {
			find = true
			break
		}
	}
	if find {
		// there are other processes in this cgroup, skip
		return nil
	}
	// no other process in this cgroup clean up
	log.Debugf("no process in cgroup %d, run cleanup", cgroupInode)
	if err := ebpfs.GetCgroupInfoMap().Delete(&cgroupInode); err != nil {
		log.Debugf("remove cgroup %d from map error: %v", cgroupInode, err)
	}
	ip, ok := w.cgroupIPMap[cgroupInode]
	if !ok {
		return fmt.Errorf("can no get ip of pid %d", pid)
	}
	if len(w.ipCgroupsMap[ip]) != 0 {
		delete(w.ipCgroupsMap[ip], cgroupInode)
	}
	if len(w.ipCgroupsMap[ip]) == 0 {
		// no process exists in current ns, remove cgroup info
		log.Debugf("remove cgroup info for %d", cgroupInode)
		delete(w.ipCgroupsMap, ip)
	}
	delete(w.cgroupIPMap, cgroupInode)
	return nil
}

func (w *processManager) OnPodStatusChanged(ip string, isInMesh bool, isAmbient bool, isZtunnel bool) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	if isZtunnel {
		_ip, _ := linux.IP2Linux(ip)
		var key uint32 = ZTUNNEL_IP_KEY
		if err := ebpfs.GetSettingsMap().Update(&key, _ip, ebpf.UpdateAny); err != nil {
			log.Errorf("update ztunnel ip error: %v", err)
		} else {
			log.Debugf("set ztunnel ip %s ok", ip)
		}
	}
	w.podIPModeMap[ip] = podInfo{
		ip:        ip,
		isInMesh:  isInMesh,
		isAmbient: isAmbient,
		isZtunnel: isZtunnel,
	}
	cgrsm, ok := w.ipCgroupsMap[ip]
	if !ok {
		return fmt.Errorf("no cgroup for ip %s found", ip)
	}
	for cg := range cgrsm {
		log.Debugf("updating pod %s's cg %d: %+v", ip, cg, w.podIPModeMap[ip])
		if err := w.writePodInfoToCgroupMap(cg, w.podIPModeMap[ip]); err != nil {
			log.Warnf("update cgroup info for podip %s error: %v", ip, err)
		}
	}
	return nil
}

func (w *processManager) Run(stop chan struct{}) error {
	netns, err := ns.GetNS(config.HostProc + "/1/ns/net")
	if err != nil {
		return err
	}
	defer netns.Close()
	err = netns.Do(func(nn ns.NetNS) error {
		return w.processWatcher.Start()
	})
	if err != nil {
		return err
	}
	os.Setenv("HOST_PROC", config.HostProc)
	ids, err := process.Pids()
	if err != nil {
		return err
	}
	for _, pid := range ids {
		err := w.onProcessAdded(uint32(pid))
		log.Debugf("init exists pid %d error: %v", pid, err)
	}
	for {
		select {
		case e := <-w.processWatcher.Events():
			if e.Err != nil {
				log.Errorf("received error from processWatcher: %v", err)
				continue
			}
			switch e.GetType() {
			case processwatcher.PROC_EVENT_FORK:
				fork := e.GetFork()
				pid := fork.ChildPid
				err := w.onProcessAdded(uint32(pid))
				if err != nil {
					log.Debugf("onProcessFork error: %v", err)
				}
			case processwatcher.PROC_EVENT_EXIT:
				e := e.GetExit()
				pid := e.ProcessPid
				err := w.onProcessExit(uint32(pid))
				if err != nil {
					log.Debugf("onProcessExit error: %v", err)
				}
			}
		case <-stop:
			w.processWatcher.Stop()
			return nil
		}
	}
}
