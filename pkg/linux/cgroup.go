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
