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
package options

import (
	"os"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/pkg/kube"
)

// NewOptions setup tasks when start up and return a kubernetes client
func NewOptions() kubernetes.Interface {
	var err error
	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}
	if config.Mode != config.ModeIstio && config.Mode != config.ModeLinkerd {
		log.Errorf("invalid mode %q, current only support istio and linkerd", config.Mode)
		os.Exit(1)
	}
	if err := ebpfs.LoadMBProgs(config.Mode, config.UseReconnect, config.Debug); err != nil {
		panic(err)
	}
	config.EbpfLoadPinnedMap, err = ebpf.LoadPinnedMap(config.LocalPodIps, &ebpf.LoadPinOptions{})
	if err != nil {
		log.Errorf("load map error: %v", err)
		os.Exit(1)
	}
	cli, err := kube.GetKubernetesClientWithFile("", "")
	if err != nil {
		panic(err)
	}
	return cli
}
