package models

import (
	"net"
)

type Host struct {
	IP     net.IP `json:"ip"`
	Port   uint16 `json:"port"`
	IsIpv6 bool
}
