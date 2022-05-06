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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	log "github.com/sirupsen/logrus"
	"istio.io/istio/cni/pkg/plugin"

	"github.com/merbridge/merbridge/config/constants"
)

// copied from https://github.com/istio/istio/blob/1.13.3/cni/pkg/plugin/plugin.go#L94-L120
// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*plugin.Config, error) {
	conf := plugin.Config{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result. Remove this if your plugin is not chained.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = cniv1.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	// End previous result parsing

	return &conf, nil
}

// references https://github.com/istio/istio/blob/1.13.3/cni/pkg/plugin/plugin.go#L205
func ignore(conf *plugin.Config, k8sArgs *plugin.K8sArgs) bool {
	ns := string(k8sArgs.K8S_POD_NAMESPACE)
	name := string(k8sArgs.K8S_POD_NAME)
	if ns != "" && name != "" {
		for _, excludeNs := range conf.Kubernetes.ExcludeNamespaces {
			if ns == excludeNs {
				log.Infof("Pod %s/%s excluded", ns, name)
				return true
			}
		}
		client, err := newKubeClient(*conf)
		if err != nil {
			log.Error(err)
			return true
		}
		pi := &plugin.PodInfo{}
		for attempt := 1; attempt <= podRetrievalMaxRetries; attempt++ {
			pi, err = getKubePodInfo(client, name, ns)
			if err == nil {
				break
			}
			log.Debugf("Failed to get %s/%s pod info: %v", ns, name, err)
			time.Sleep(podRetrievalInterval)
		}
		if err != nil {
			log.Errorf("Failed to get %s/%s pod info: %v", ns, name, err)
			return true
		}
		return ignorePod(ns, name, pi)
	}
	log.Debugf("Not a kubernetes pod")
	return true
}

func ignorePod(namespace, name string, pod *plugin.PodInfo) bool {
	if val, ok := pod.ProxyEnvironments["DISABLE_ENVOY"]; ok {
		if val, err := strconv.ParseBool(val); err == nil && val {
			log.Infof("Pod %s/%s excluded due to DISABLE_ENVOY on istio-proxy", namespace, name)
			return true
		}
	}
	if len(pod.Containers) > 1 {
		if val, ok := pod.Annotations[injectAnnotationKey]; ok {
			if injectEnabled, err := strconv.ParseBool(val); err == nil {
				if !injectEnabled {
					log.Infof("Pod %s/%s excluded due to inject-disabled annotation", namespace, name)
					return true
				}
			}
		}
		if _, ok := pod.Annotations[sidecarStatusKey]; !ok {
			log.Infof("Pod %s/%s excluded due to not containing sidecar annotation", namespace, name)
			return true
		}
		return false
	}
	log.Infof("Pod %s/%s excluded because it only has %d containers", namespace, name, len(pod.Containers))
	return true
}

func CmdAdd(args *skel.CmdArgs) (err error) {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Errorf("merbridge-cni cmdAdd failed to parse config %v %v", string(args.StdinData), err)
		return err
	}
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}

	if ignore(conf, &k8sArgs) {
		// ignore uninjected pods
		return nil
	}

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/merbridge-cni.sock")
			},
		},
	}
	http.DefaultClient = &httpc
	bs, _ := json.Marshal(args)
	body := bytes.NewReader(bs)
	_, err = http.Post("http://merbridge-cni"+constants.CNICreatePodURL, "application/json", body)
	if err != nil {
		return err
	}

	var result *cniv1.Result
	if conf.PrevResult == nil {
		result = &cniv1.Result{
			CNIVersion: cniv1.ImplementedSpecVersion,
		}
	} else {
		// Pass through the result for the next plugin
		result = conf.PrevResult
	}
	return types.PrintResult(result, conf.CNIVersion)
}

func CmdCheck(args *skel.CmdArgs) (err error) {
	return err
}

func CmdDelete(args *skel.CmdArgs) (err error) {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/merbridge-cni.sock")
			},
		},
	}
	http.DefaultClient = &httpc
	bs, _ := json.Marshal(args)
	body := bytes.NewReader(bs)
	_, err = http.Post("http://merbridge-cni"+constants.CNIDeletePodURL, "application/json", body)
	return err
}
