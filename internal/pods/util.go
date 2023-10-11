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
	v1 "k8s.io/api/core/v1"
)

func IsIstioInjectedSidecar(pod *v1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" && len(pod.Spec.Containers) != 1 {
			return true
		}
	}
	return false
}

func IsLinkerdInjectedSidecar(pod *v1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "linkerd-proxy" && len(pod.Spec.Containers) != 1 {
			return true
		}
	}
	return false
}

func IsKumaInjectedSidecar(pod *v1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "kuma-sidecar" && len(pod.Spec.Containers) != 1 {
			return true
		}
	}
	return false
}

func IsOsmInjectedSidecar(pod *v1.Pod) bool {
	if _, found := pod.Labels["osm-proxy-uuid"]; found {
		return true
	}
	return false
}
