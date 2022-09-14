package health_check

import (
	"net/http"
	"sync"

	"github.com/Kodik77rus/health-check/internal/pkg/docker_stats"
	"github.com/Kodik77rus/health-check/internal/pkg/models"
	"github.com/Kodik77rus/health-check/internal/pkg/postgres"
	"github.com/Kodik77rus/health-check/internal/pkg/socket_pinger"
	"github.com/Kodik77rus/health-check/internal/pkg/utils"
	"github.com/rs/zerolog/log"
)

type HealthCheck struct{}

func InitHealthCheck(
	postgres *postgres.Postgres,
	socketPinger *socket_pinger.SocketPinger,
	dockerStat docker_stats.DockerStat,
	mu *http.ServeMux,
) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			hosts, err := postgres.HostsRepo().GetAll()
			if err != nil {
				log.Error().Err(err).Msg("failed load hosts")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			hostsLen := len(hosts)
			hostMap := make(map[string]string, hostsLen)

			if hostsLen > 0 {
				wg := sync.WaitGroup{}
				mu := sync.Mutex{}

				wg.Add(hostsLen)

				//make something like throttler
				for _, host := range hosts {
					go func(host *models.Host) {
						defer wg.Done()
						if err := socketPinger.Ping(host); err != nil {
							log.Debug().Err(err).Interface("host", host).Msg("ping host error")
							mu.Lock()
							hostMap[host.IP.String()] = "not ok"
							mu.Unlock()
							return
						}
						mu.Lock()
						hostMap[host.IP.String()] = "ok"
						mu.Unlock()
					}(host)
				}

				wg.Wait()
			}

			containersInfo, err := dockerStat.GetContainersInfo()
			if err != nil {
				log.Error().Err(err).Msg("can't check docker containers")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			dockerMap := make(map[string]string, len(containersInfo))

			for _, container := range containersInfo {
				if container.State != "running" {
					dockerMap[container.Name] = "not running"
					continue
				}
				dockerMap[container.Name] = container.State
			}

			respMsg := map[string]map[string]string{
				"hosts":   hostMap,
				"dockers": dockerMap,
			}

			resp, err := utils.JsonMarshal(respMsg)
			if err != nil {
				log.Error().Err(err).Interface("health check", respMsg).Msg("can't marshal response msg")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(resp)
		case http.MethodPost:
			var hostDto models.Host

			if err := utils.JsonDecode(r.Body, &hostDto); err != nil {
				log.Error().Err(err).Msg("can't unmarshal request body")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			ip := hostDto.IP.String()

			if ok := utils.IsIP(ip); !ok {
				log.Debug().Interface("host", hostDto).Msg("not ip address")
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if ok := utils.IsIPv6(ip); ok {
				hostDto.IsIpv6 = true
			}

			if err := postgres.HostsRepo().Insert(hostDto); err != nil {
				log.Error().Err(err).Interface("host", hostDto).Msg("can't insert in db")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case http.MethodDelete:
			var hostDto models.Host

			if err := utils.JsonDecode(r.Body, &hostDto); err != nil {
				log.Error().Err(err).Msg("can't unmarshal request body")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			rows, err := postgres.HostsRepo().Delete(hostDto)
			if err != nil {
				log.Error().Err(err).Interface("host", hostDto).Msg("can't delete from db")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if rows == 0 {
				log.Debug().Msg("host not found")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}

	mu.Handle("/health", http.HandlerFunc(handler))
}
