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
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestIP2Linux(t *testing.T) {
	cases := []struct {
		ip      string
		wantErr bool
		want    uint32
	}{
		{
			ip:   "127.0.0.1",
			want: (1 << 24) | (0 << 16) | (0 << 8) | (127 << 0),
		},
		{
			ip:   "10.244.0.7",
			want: (7 << 24) | (0 << 16) | (244 << 8) | (10 << 0),
		},
		{
			ip:      "127.0.0.",
			wantErr: true,
			// want: 16777343,
		},
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			ip, err := IP2Linux(c.ip)
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.want, *(*uint32)(unsafe.Add(ip, 12)))
			}
		})
	}
}
