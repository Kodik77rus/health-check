package utils

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

func StrToInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func AddrFromSlice(IP net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(IP)
	if !ok {
		return netip.Addr{}, errors.Errorf("remote host IPv6 %v slice's length is not 4 or 16", addr)
	}
	return addr, nil
}

func ParseDuration(str string) (time.Duration, error) {
	return time.ParseDuration(str)
}
