package pods

import v1 "k8s.io/api/core/v1"

func IsInjectedSidecar(pod *v1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if (c.Name == "istio-proxy" && len(pod.Spec.Containers) != 1) || (c.Name == "linkerd-proxy" && len(pod.Spec.Containers) != 1) {
			return true
		}
	}
	return false
}
