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
	"encoding/json"
	"fmt"

	"istio.io/istio/cni/pkg/plugin"

	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

// Args contains information necessary for the CNI plugin to work with Istio
// as well as Kuma service meshes
type Args struct {
	ServiceMeshMode string `json:"serviceMeshMode"`
}

// Config is a *plugin.Config enriched with Args structure containing information
// like if CNI is working in context of Istio or Kuma
type Config struct {
	*plugin.Config

	Args Args `json:"args"`
}

// copied from https://github.com/istio/istio/blob/1.13.3/cni/pkg/plugin/plugin.go#L94-L120
// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*Config, error) {
	conf := Config{}

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
