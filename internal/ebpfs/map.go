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
package ebpfs

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/merbridge/merbridge/config"
)

var EbpfLoadPinnedMap *ebpf.Map

func InitLoadPinnedMap() error {
	var err error
	EbpfLoadPinnedMap, err = ebpf.LoadPinnedMap(config.LocalPodIps, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("load map error: %v", err)
	}
	return nil
}

func GetPinnedMap() *ebpf.Map {
	return EbpfLoadPinnedMap
}
