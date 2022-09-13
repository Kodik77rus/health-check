package utils

import (
	"net"
	"net/netip"
	"strconv"
	"time"
)

func StrToInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func AddrFromSlice(IP net.IP) (netip.Addr, bool) {
	return netip.AddrFromSlice(IP)
}

func ParseDuration(str string) (time.Duration, error) {
	return time.ParseDuration(str)
}
