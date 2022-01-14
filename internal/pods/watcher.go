package pods

import (
	"time"

	kubeinformer "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
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

func NewWatcher(client kubernetes.Interface, currentNodeName string,
	onAddFunc func(obj interface{}),
	onUpdateFunc func(oldObj, newObj interface{}),
	onDeleteFunc func(obj interface{})) Watcher {
	return &watcher{
		client:          client,
		currentNodeName: currentNodeName,
		onAddFunc:       onAddFunc,
		onUpdateFunc:    onUpdateFunc,
		onDeleteFunc:    onDeleteFunc,
		stop:            make(chan struct{}),
	}
}
