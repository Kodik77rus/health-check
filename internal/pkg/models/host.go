package models

import (
	"net"
)

type Host struct {
	IP     net.IP `json:"ip"`
	IsIpv6 bool
}
