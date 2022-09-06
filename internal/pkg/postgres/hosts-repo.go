package postgres

type HostsRepo struct {
	postgres *Postgres
}

func (h *HostsRepo) Get() error {
	return nil
}

func (h *HostsRepo) Delete() error {
	return nil
}
