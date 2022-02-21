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
	"time"

	kubeinformer "k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"k8s.io/client-go/kubernetes"
)

type WatcherAction interface {
	Start() error
	Shutdown()
}

type Watcher struct {
	Client          kubernetes.Interface
	CurrentNodeName string
	OnAddFunc       func(obj interface{})
	OnUpdateFunc    func(oldObj, newObj interface{})
	OnDeleteFunc    func(obj interface{})
	Stop            chan struct{}
}

func (w *Watcher) Start() error {
	kubeInformerFactory := kubeinformer.NewSharedInformerFactory(w.Client, 30*time.Second)
	kubeInformerFactory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.OnAddFunc,
		UpdateFunc: w.OnUpdateFunc,
		DeleteFunc: w.OnDeleteFunc,
	})
	kubeInformerFactory.Start(w.Stop)
	return nil
}

func (w *Watcher) Shutdown() {
	close(w.Stop)
}

func NewWatcher(watch Watcher) *Watcher {
	return &Watcher{
		Client:          watch.Client,
		CurrentNodeName: watch.CurrentNodeName,
		OnAddFunc:       watch.OnAddFunc,
		OnUpdateFunc:    watch.OnUpdateFunc,
		OnDeleteFunc:    watch.OnDeleteFunc,
		Stop:            make(chan struct{}),
	}
}
