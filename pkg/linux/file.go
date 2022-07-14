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
	"fmt"
	"os"
	"syscall"
)

func GetFileInode(path string) (uint64, error) {
	f, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("failed to get the inode of %s", path)
	}
	stat, ok := f.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not syscall.Stat_t")
	}
	return stat.Ino, nil
}
