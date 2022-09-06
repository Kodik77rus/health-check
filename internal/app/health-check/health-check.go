package healthcheck

import (
	"net/http"

	"github.com/Kodik77rus/health-check/internal/app/pkg/env"
	"github.com/Kodik77rus/health-check/internal/app/pkg/postgres"
)

type HealthCheck struct {
	mu  *http.ServeMux
	env *env.Env
}

func InitHealthCheck(
	postgres *postgres.Postgres,
	mu *http.ServeMux,
) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
		case http.MethodDelete:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}

	mu.Handle("/health", http.HandlerFunc(handler))
}
