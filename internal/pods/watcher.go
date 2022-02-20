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
package pods

import (
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	kubeinformer "k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/pkg/linux"
)

type Watcher interface {
	Start() error
	Stop()
}

type watcher struct {
	client          kubernetes.Interface
	currentNodeName string
	onAddFunc       func(obj interface{})
	onUpdateFunc    func(oldObj, newObj interface{})
	onDeleteFunc    func(obj interface{})
	stop            chan struct{}
}

func (w *watcher) Start() error {
	kubeInformerFactory := kubeinformer.NewSharedInformerFactory(w.client, 30*time.Second)
	kubeInformerFactory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.onAddFunc,
		UpdateFunc: w.onUpdateFunc,
		DeleteFunc: w.onDeleteFunc,
	})
	kubeInformerFactory.Start(w.stop)
	return nil
}

func (w *watcher) Stop() {
	close(w.stop)
}

func NewWatcher(client kubernetes.Interface) Watcher {
	locaName, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	return &watcher{
		client:          client,
		currentNodeName: locaName,
		onAddFunc:       AddFunc,
		onUpdateFunc:    UpdateFunc,
		onDeleteFunc:    DeleteFunc,
		stop:            make(chan struct{}),
	}
}

func AddFunc(obj interface{}) {
	if pod, ok := obj.(*v1.Pod); ok {
		if config.Mode == config.ModeIstio && !IsIstioInjectedSidecar(pod) {
			return
		}
		if config.Mode == config.ModeLinkerd && !IsLinkerdInjectedSidecar(pod) {
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
			err := config.EbpfLoadPinnedMap.Update(_ip, uint32(0), ebpf.UpdateAny)
			if err != nil {
				log.Errorf("update local_pod_ips %s error: %v", pod.Status.PodIP, err)
			}
		}
	}
}

func UpdateFunc(old, newest interface{}) {
	AddFunc(newest)
}

func DeleteFunc(obj interface{}) {
	if pod, ok := obj.(*v1.Pod); ok {
		log.Debugf("got pod delete %s/%s", pod.Namespace, pod.Name)
		_ip, _ := linux.IP2Linux(pod.Status.PodIP)
		_ = config.EbpfLoadPinnedMap.Delete(_ip)
	}
}
