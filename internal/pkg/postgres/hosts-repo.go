package postgres

import (
	"fmt"

	"github.com/Kodik77rus/health-check/internal/pkg/models"
	"github.com/jackc/pgtype"
)

type HostsRepo struct {
	postgres *Postgres
}

func (h *HostsRepo) GetAll() ([]models.Host, error) {
	rows, err := h.postgres.db.Query("select * from hosts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hosts := make([]models.Host, 10)

	for rows.Next() {
		var (
			ip   pgtype.Inet
			host models.Host
		)

		err := rows.Scan(&ip, &host.IsIpv6)
		if err != nil {
			fmt.Println(err)
			continue
		}

		host.IP = ip.IPNet.IP

		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (h *HostsRepo) Insert(host models.Host) error {
	_, err := h.postgres.db.Exec(
		"insert into hosts (ip, ipv6) values ($1, $2)",
		host.IP.String(), host.IsIpv6,
	)
	if err != nil {
		return err
	}
	return nil
}

func (h *HostsRepo) Delete(host models.Host) (int64, error) {
	result, err := h.postgres.db.Exec(
		"delete from hosts where ip = $1",
		host.IP.String(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
