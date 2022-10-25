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

package config

import (
	"os"
)

const (
	ModeIstio       = "istio"
	ModeLinkerd     = "linkerd"
	ModeKuma        = "kuma"
	ModeOsm         = "osm"
	LocalPodIps     = "/sys/fs/bpf/local_pod_ips"
	PairOriginalDst = "/sys/fs/bpf/pair_original_dst"
	CgroupInfoMap   = "/sys/fs/bpf/cgroup_info_map"
	SettingsMap     = "/sys/fs/bpf/settings"
)

var (
	Mode             string
	IpsFile          string // not used
	UseReconnect     = true
	Debug            = false
	EnableCNI        = false
	EnableIPV4       = getEnvOrDefault("ENABLE_IPV4", "true") == "true"
	EnableIPV6       = getEnvOrDefault("ENABLE_IPV6", "false") == "true"
	IsKind           = false // is Kubernetes running in Docker
	HostProc         string
	CNIBinDir        string
	CNIConfigDir     string
	HostVarRun       string
	KubeConfig       string
	Context          string
	EnableHotRestart = false
)

func getEnvOrDefault(name, defaultValue string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return defaultValue
}
