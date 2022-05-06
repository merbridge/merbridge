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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseConfig(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		expect      *podConfig
	}{
		{
			name:        "empty",
			annotations: map[string]string{},
			expect: &podConfig{
				statusPort: 15021,
				excludeInPorts: [MaxItemLen]uint16{
					15090, 15006, 15001, 15000,
				},
			},
		},
		{
			name: "excludeInboundPorts",
			annotations: map[string]string{
				"traffic.sidecar.istio.io/excludeInboundPorts": "12345,80",
			},
			expect: &podConfig{
				statusPort: 15021,
				excludeInPorts: [MaxItemLen]uint16{
					15090, 15006, 15001, 15000,
					12345,
					80,
				},
			},
		},
		{
			name: "excludeOutboundIPRanges",
			annotations: map[string]string{
				"traffic.sidecar.istio.io/excludeOutboundIPRanges": "192.168.0.0/16,172.31.0.1/20",
			},
			expect: &podConfig{
				statusPort: 15021,
				excludeInPorts: [MaxItemLen]uint16{
					15090, 15006, 15001, 15000,
				},
				excludeOutRanges: [MaxItemLen]cidr{
					{
						net:  0x0000a8c0,
						mask: 16,
					},
					{
						net:  0x00001fac,
						mask: 20,
					},
				},
			},
		},
		{
			name: "excludeOutboundIPRanges *",
			annotations: map[string]string{
				"traffic.sidecar.istio.io/excludeOutboundIPRanges": "*",
			},
			expect: &podConfig{
				statusPort: 15021,
				excludeInPorts: [MaxItemLen]uint16{
					15090, 15006, 15001, 15000,
				},
				excludeOutRanges: [MaxItemLen]cidr{
					{
						net:  0,
						mask: 0,
					},
				},
			},
		},
		{
			name: "excludeOutboundIPRanges invalid",
			annotations: map[string]string{
				"traffic.sidecar.istio.io/excludeOutboundIPRanges": "192.168.0.0/16,1721.0.1/20",
			},
			expect: &podConfig{
				statusPort: 15021,
				excludeInPorts: [MaxItemLen]uint16{
					15090, 15006, 15001, 15000,
				},
				excludeOutRanges: [MaxItemLen]cidr{
					{
						net:  0x0000a8c0,
						mask: 16,
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := podConfig{}
			parsePodConfigFromAnnotations(c.annotations, &out)
			assert.Equal(t, c.expect, &out)
		})
	}
}
