package validator

import (
	"net"
	"strings"
)

type Validator struct{}

func (v Validator) IsIPv6(str string) bool {
	return strings.Contains(str, ":")
}

func (v Validator) IsIP(str string) bool {
	return net.ParseIP(str) != nil
}
