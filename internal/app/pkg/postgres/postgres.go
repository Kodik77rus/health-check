package postgres

import (
	"database/sql"
	"fmt"

	"github.com/Kodik77rus/health-check/internal/app/pkg/env"
	_ "github.com/lib/pq"
)

type Postgres struct {
	env *env.Env
	db  *sql.DB
}

func InitPostgres(env *env.Env) (*Postgres, error) {
	db := &Postgres{
		env: env,
	}

	err := db.connect()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (p *Postgres) connect() error {
	conn, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=disable",
			p.env.Postgres_User,
			p.env.Postgres_Password,
			p.env.Postgres_Host,
			p.env.Postgres_Port,
			p.env.Postgres_Dbname,
		),
	)
	if err != nil {
		return err
	}

	if err := conn.Ping(); err != nil {
		return err
	}

	p.db = conn
	return nil
}

func (p *Postgres) Close() {
	if err := p.db.Ping(); err != nil {
		return
	}
	p.db.Close()
}
