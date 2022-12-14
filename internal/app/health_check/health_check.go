package health_check

import (
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/Kodik77rus/health-check/internal/pkg/docker_controller"
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
	dockerController docker_controller.DockerController,
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

				for _, host := range hosts {
					go func(host *models.Host) {
						defer wg.Done()
						if err := socketPinger.Ping(host); err != nil {
							log.Error().Err(err).Interface("host", host).Msg("ping host error")
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

			containersInfo, err := dockerController.GetContainersInfo()
			if err != nil {
				log.Error().Err(err).Msg("can't check docker containers")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			dockerMap := make(map[string]string, len(containersInfo))

			for _, container := range containersInfo {
				if container.State != "running" {
					log.Error().Interface("docker container", container).Msg("container not working")
					dockerMap[container.Name[0]] = "not running"
					continue
				}
				dockerMap[container.Name[0]] = container.State
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

			if _, err := w.Write(resp); err != nil {
				log.Error().Err(err).Interface("health check", respMsg).Msg("can't send response msg")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("read body err")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if ok := utils.IsValidJson(body); !ok {
				log.Debug().Msg("invalid json object")
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var hostDto models.Host

			if err := utils.JsonUnmarshal(body, &hostDto); err != nil {
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
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("read body err")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if ok := utils.IsValidJson(body); !ok {
				log.Debug().Msg("invalid json object")
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var hostDto models.Host

			if err := utils.JsonUnmarshal(body, &hostDto); err != nil {
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
