package models

import "net"

type Host struct {
	host   net.IPNet
	IsIpv6 bool
}
