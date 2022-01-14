package linux

import (
	"fmt"
	"net"
	"unsafe"
)

func IP2Linux(ipstr string) (uint32, error) {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0, fmt.Errorf("error parse ip: %s", ipstr)
	}
	return *(*uint32)(unsafe.Pointer(&ip[12])), nil
}
