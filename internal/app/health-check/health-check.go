package healthcheck

import (
	"io/ioutil"
	"net/http"
	"sync"

	healthchecker "github.com/Kodik77rus/health-check/internal/pkg/health-checker"
	"github.com/Kodik77rus/health-check/internal/pkg/models"
	"github.com/Kodik77rus/health-check/internal/pkg/postgres"
	"github.com/Kodik77rus/health-check/internal/pkg/utils"
	"github.com/Kodik77rus/health-check/internal/pkg/validator"
)

type HealthCheck struct{}

func InitHealthCheck(
	postgres *postgres.Postgres,
	healthchecker healthchecker.Healthchecker,
	validator validator.Validator,
	mu *http.ServeMux,
) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			hosts, err := postgres.HostsRepo().GetAll()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			respMap := make(map[string]string)
			wg := sync.WaitGroup{}
			mu := sync.Mutex{}

			wg.Add(len(hosts))

			for _, host := range hosts {
				go func(host models.Host) {
					defer wg.Done()
					if err := healthchecker.Check(host); err != nil {
						mu.Lock()
						respMap[host.IP.String()] = err.Error()
						mu.Unlock()
						return
					}

					mu.Lock()
					respMap[host.IP.String()] = "ok"
					mu.Unlock()
				}(host)
			}

			wg.Wait()

			resp, err := utils.JsonMarshal(respMap)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(resp)
		case http.MethodPost:
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var hostDto models.Host

			if err := utils.JsonUnmarshal(body, &hostDto); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			ip := hostDto.IP.String()

			if ok := validator.IsIP(ip); !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if ok := validator.IsPort(hostDto.Port); !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if ok := validator.IsIPv6(ip); ok {
				hostDto.IsIpv6 = true
			}

			if err := postgres.HostsRepo().Insert(hostDto); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case http.MethodDelete:
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var hostDto models.Host

			if err := utils.JsonUnmarshal(body, &hostDto); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			rows, err := postgres.HostsRepo().Delete(hostDto)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if rows == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}

	mu.Handle("/health", http.HandlerFunc(handler))
}
