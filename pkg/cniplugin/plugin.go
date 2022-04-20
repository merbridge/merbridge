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

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	log "github.com/sirupsen/logrus"
	"istio.io/istio/cni/pkg/plugin"

	"github.com/merbridge/merbridge/config/constants"
)

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

func CmdAdd(args *skel.CmdArgs) (err error) {
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

	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Errorf("istio-cni cmdAdd failed to parse config %v %v", string(args.StdinData), err)
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
