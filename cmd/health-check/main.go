package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Kodik77rus/health-check/internal/app/health_check"
	"github.com/Kodik77rus/health-check/internal/pkg/docker_controller"
	"github.com/Kodik77rus/health-check/internal/pkg/env"
	"github.com/Kodik77rus/health-check/internal/pkg/postgres"
	"github.com/Kodik77rus/health-check/internal/pkg/socket_pinger"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
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
	fmt.Print(env)

	initZeroLogger(env)

	postgres, err := postgres.InitPostgres(env)
	if err != nil {
		return errors.Wrap(err, "can't init postgres")
	}

	mux := &http.ServeMux{}

	socketPinger := socket_pinger.InitSocketPinger(env)

	health_check.InitHealthCheck(
		postgres,
		socketPinger,
		docker_controller.DockerController{},
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

func initZeroLogger(env *env.Env) {
	zerolog.TimeFieldFormat = "2006-01-02 15:04:05.999"

	lvl, err := zerolog.ParseLevel(env.Log_LVL)
	if err != nil {
		log.Println("init zero logger : error parse config level", "err: ", err)
		lvl = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(lvl)
}
