package models

import (
	"net"
)

type Host struct {
	IP     net.IP `json:"ip"`
	Port   int    `json:"port"`
	IsIpv6 bool
}
