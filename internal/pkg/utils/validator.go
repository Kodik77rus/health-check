package utils

import (
	"net"
	"strings"
)

func IsIPv6(str string) bool {
	return strings.Contains(str, ":")
}

func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}
