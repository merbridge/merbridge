package pods

import v1 "k8s.io/api/core/v1"

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
