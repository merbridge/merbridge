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
package cniplugin

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/cni/pkg/plugin"
	"istio.io/istio/pilot/cmd/pilot-agent/options"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	injectAnnotationKey    = annotation.SidecarInject.Name
	sidecarStatusKey       = annotation.SidecarStatus.Name
	podRetrievalMaxRetries = 30
	podRetrievalInterval   = 1 * time.Second
)

// copied from https://github.com/istio/istio/blob/1.13.3/cni/pkg/plugin/plugin.go#L94-L120
// newKubeClient returns a Kubernetes client
func newKubeClient(conf plugin.Config) (*kubernetes.Clientset, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	config, err := kube.DefaultRestConfig(kubeconfig, "")
	if err != nil {
		log.Errorf("Failed setting up kubernetes client with kubeconfig %s", kubeconfig)
		return nil, err
	}

	log.Debugf("merbridge-cni set up kubernetes client with kubeconfig %s", kubeconfig)

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

// references https://github.com/istio/istio/blob/1.13.3/cni/pkg/plugin/kubernetes.go#L65-L110
// getKubePodInfo returns information of a POD
func getKubePodInfo(client *kubernetes.Clientset, podName, podNamespace string) (*plugin.PodInfo, error) {
	pod, err := client.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	pi := &plugin.PodInfo{
		Containers:        make([]string, len(pod.Spec.Containers)),
		Annotations:       pod.Annotations,
		ProxyEnvironments: make(map[string]string),
	}
	for containerIdx, container := range pod.Spec.Containers {
		log.Debugf("Inspecting pod %v/%v container %v", podNamespace, podName, container.Name)
		pi.Containers[containerIdx] = container.Name

		if container.Name == "istio-proxy" {
			// don't include ports from istio-proxy in the redirect ports
			// Get proxy container env variable, and extract out ProxyConfig from it.
			for _, e := range container.Env {
				pi.ProxyEnvironments[e.Name] = e.Value
				if e.Name == options.ProxyConfigEnv {
					proxyConfig := mesh.DefaultProxyConfig()
					mc := &meshconfig.MeshConfig{
						DefaultConfig: proxyConfig,
					}
					mc, err := mesh.ApplyProxyConfig(e.Value, mc)
					if err != nil {
						log.Warnf("Failed to apply proxy config for %v/%v: %+v", pod.Namespace, pod.Name, err)
					} else {
						pi.ProxyConfig = mc.DefaultConfig
					}
					break
				}
			}
			continue
		}
	}
	log.Debugf("Pod %v/%v info: \n%+v", podNamespace, podName, pi)

	return pi, nil
}
