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

func IsCurrentNodeIP(ipstr string) bool {
	ifaces, _ := net.Interfaces()
	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.String() == ipstr {
					return true
				}
			case *net.IPAddr:
				if v.String() == ipstr {
					return true
				}
			}
			// process IP address
		}
	}
	return false
}
