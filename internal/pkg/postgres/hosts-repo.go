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

	var ip pgtype.Inet
	hosts := []models.Host{}

	for rows.Next() {
		host := models.Host{}

		err := rows.Scan(&ip, &host.Port, &host.IsIpv6)
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
		"insert into hosts (ip, port, ipv6) values ($1, $2, $3)",
		host.IP.String(), host.Port, host.IsIpv6,
	)
	if err != nil {
		fmt.Println(err)
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
