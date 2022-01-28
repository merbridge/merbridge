package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/internal/pods"
	"github.com/merbridge/merbridge/pkg/kube"
	"github.com/merbridge/merbridge/pkg/linux"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp:       false,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		DisableColors:          true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			fs := strings.Split(f.File, "/")
			filename := fs[len(fs)-1]
			ff := strings.Split(f.Function, "/")
			_f := ff[len(ff)-1]
			return fmt.Sprintf("%s()", _f), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)
}

var currentNodeIP string // for cache

const (
	modeIstio   = "istio"
	modeLinkerd = "linkerd"
)

func main() {
	mode := ""
	debug := false
	isKind := false // is Run Kubernetes in Docker
	flag.StringVar(&mode, "m", modeIstio, "Service mesh mode, current support istio and linkerd")
	flag.BoolVar(&debug, "d", false, "Debug mode")
	flag.BoolVar(&isKind, "kind", false, "Kubernetes in Kind mode")
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	if mode != modeIstio && mode != modeLinkerd {
		log.Errorf("invalid mode %q, current only support istio and linkerd", mode)
		os.Exit(1)
	}
	if err := ebpfs.LoadMBProgs(mode, debug); err != nil {
		panic(err)
	}
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/local_pod_ips", &ebpf.LoadPinOptions{})
	if err != nil {
		log.Errorf("load map error: %v", err)
		os.Exit(1)
	}
	cli, err := kube.GetKubernetesClientWithFile("", "")
	if err != nil {
		panic(err)
	}
	locaName, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	addFunc := func(obj interface{}) {
		if pod, ok := obj.(*v1.Pod); ok {
			if mode == modeIstio && !pods.IsIstioInjectedSidecar(pod) {
				return
			}
			if mode == modeLinkerd && !pods.IsLinkerdInjectedSidecar(pod) {
				return
			}
			log.Debugf("got pod updated %s/%s", pod.Namespace, pod.Name)
			podHostIP := pod.Status.HostIP
			if currentNodeIP == "" {
				if linux.IsCurrentNodeIP(podHostIP) {
					currentNodeIP = podHostIP
				}
			}
			if podHostIP == currentNodeIP || isKind {
				_ip, _ := linux.IP2Linux(pod.Status.PodIP)
				log.Infof("update local_pod_ips with ip: %s", pod.Status.PodIP)
				err := m.Update(_ip, uint32(0), ebpf.UpdateAny)
				if err != nil {
					log.Errorf("update local_pod_ips %s error: %v", pod.Status.PodIP, err)
				}
			}
		}
	}

	updateFunc := func(old, new interface{}) {
		addFunc(new)
	}
	deleteFunc := func(obj interface{}) {
		if pod, ok := obj.(*v1.Pod); ok {
			log.Debugf("got pod delete %s/%s", pod.Namespace, pod.Name)
			_ip, _ := linux.IP2Linux(pod.Status.PodIP)
			_ = m.Delete(_ip)
		}
	}
	w := pods.NewWatcher(cli, locaName, addFunc, updateFunc, deleteFunc)
	_ = w.Start()
	log.Info("pod watcher ready")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	<-ch
	w.Stop()
	_ = ebpfs.UnLoadMBProgs()
}
