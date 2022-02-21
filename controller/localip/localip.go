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
package localip

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/internal/pods"
	"github.com/merbridge/merbridge/pkg/linux"
)

func RunLocalIPController(client kubernetes.Interface) error {
	var err error

	if err = ebpfs.InitLoadPinnedMap(); err != nil {
		return fmt.Errorf("load failed: %v", err)
	}

	w := pods.NewWatcher(createLocalIPController(client))

	if err = w.Start(); err != nil {
		return fmt.Errorf("start watcher failed: %v", err)
	}

	log.Info("Pod Watcher Ready")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	<-ch
	w.Shutdown()

	if err = ebpfs.UnLoadMBProgs(); err != nil {
		return fmt.Errorf("unload failed: %v", err)
	}
	log.Info("Pod Watcher Down")
	return nil
}

func createLocalIPController(client kubernetes.Interface) pods.Watcher {
	locaName, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return pods.Watcher{
		Client:          client,
		CurrentNodeName: locaName,
		OnAddFunc:       addFunc,
		OnUpdateFunc:    updateFunc,
		OnDeleteFunc:    deleteFunc,
	}
}

func addFunc(obj interface{}) {
	if pod, ok := obj.(*v1.Pod); ok {
		if config.Mode == config.ModeIstio && !pods.IsIstioInjectedSidecar(pod) {
			return
		}
		if config.Mode == config.ModeLinkerd && !pods.IsLinkerdInjectedSidecar(pod) {
			return
		}
		log.Debugf("got pod updated %s/%s", pod.Namespace, pod.Name)
		podHostIP := pod.Status.HostIP
		if config.CurrentNodeIP == "" {
			if linux.IsCurrentNodeIP(podHostIP, config.IpsFile) {
				config.CurrentNodeIP = podHostIP
			}
		}
		if podHostIP == config.CurrentNodeIP || config.IsKind {
			_ip, _ := linux.IP2Linux(pod.Status.PodIP)
			log.Infof("update local_pod_ips with ip: %s", pod.Status.PodIP)
			err := ebpfs.GetPinnedMap().Update(_ip, uint32(0), ebpf.UpdateAny)
			if err != nil {
				log.Errorf("update local_pod_ips %s error: %v", pod.Status.PodIP, err)
			}
		}
	}
}

func updateFunc(old, newest interface{}) {
	addFunc(newest)
}

func deleteFunc(obj interface{}) {
	if pod, ok := obj.(*v1.Pod); ok {
		log.Debugf("got pod delete %s/%s", pod.Namespace, pod.Name)
		_ip, _ := linux.IP2Linux(pod.Status.PodIP)
		_ = ebpfs.GetPinnedMap().Delete(_ip)
	}
}
