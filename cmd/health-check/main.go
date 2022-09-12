package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Kodik77rus/health-check/internal/app/health_check"
	"github.com/Kodik77rus/health-check/internal/pkg/docker_stats"
	"github.com/Kodik77rus/health-check/internal/pkg/env"
	"github.com/Kodik77rus/health-check/internal/pkg/postgres"
	"github.com/Kodik77rus/health-check/internal/pkg/socket_pinger"
	"github.com/pkg/errors"
)

func main() {
	if err := start(); err != nil {
		log.Println("main : shutting down", "err: ", err)
		os.Exit(1)
	}
}

func start() error {
	env, err := env.InitEnv()
	if err != nil {
		return errors.Wrap(err, "can't load env")
	}

	postgres, err := postgres.InitPostgres(env)
	if err != nil {
		return errors.Wrap(err, "can't init postgres")
	}

	mux := &http.ServeMux{}

	socketPinger, err := socket_pinger.InitSocketPinger()
	if err != nil {
		return errors.Wrap(err, "can't init socket pinger")
	}

	health_check.InitHealthCheck(
		postgres,
		socketPinger,
		docker_stats.DockerStat{},
		mux,
	)

	if err := http.ListenAndServe(
		fmt.Sprint(":", env.Port),
		mux,
	); err != nil {
		return err
	}

	return nil
}
