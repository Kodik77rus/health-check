package healthchecker

import (
	"fmt"
	"net"
	"time"

	"github.com/Kodik77rus/health-check/internal/pkg/models"
)

type Healthchecker struct{}

func (e *Healthchecker) Check(host models.Host) error {
	var network string

	if host.IsIpv6 {
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	conn, err := net.DialTimeout(
		network,
		fmt.Sprint(host.IP, ":", host.Port),
		5*time.Second,
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}
