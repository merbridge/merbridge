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

const (
	ModeIstio   = "istio"
	ModeLinkerd = "linkerd"
	LocalPodIps = "/sys/fs/bpf/local_pod_ips"
)

var (
	CurrentNodeIP string
	Mode          string
	IpsFile       string
	UseReconnect  = true
	Debug         = false
	EnableCNI     = false
	IsKind        = false // is Run Kubernetes in Docker
	HostProc      string
	CNIBinDir     string
	CNIConfigDir  string
	HostVarRun    string
)
