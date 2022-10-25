package linux

import (
	"os"
	"strings"
)

func GetCgroup2MountPath(proc string) (string, error) {
	ms, err := os.ReadFile(proc + "/mounts")
	if err != nil {
		return "", err
	}
	mss := strings.Split(string(ms), "\n")
	for _, m := range mss {
		if strings.Contains(m, "cgroup2 ") {
			return strings.Split(m, " ")[1], nil
		}
	}
	return "", nil
}

func GetCgroupSystemdMountPath(proc string) (string, error) {
	ms, err := os.ReadFile(proc + "/mounts")
	if err != nil {
		return "", err
	}
	mss := strings.Split(string(ms), "\n")
	for _, m := range mss {
		if strings.HasPrefix(m, "cgroup ") && strings.Contains(m, "systemd") {
			return strings.Split(m, " ")[1], nil
		}
	}
	return "", nil
}
