package linux

import (
	"testing"

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
			want: 16777343,
		},
		{
			ip:   "10.244.0.7",
			want: 117502986,
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
			}
			assert.Equal(t, c.want, ip)
		})
	}
}
