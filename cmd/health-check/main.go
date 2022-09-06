package main

import (
	"log"
	"os"

	"github.com/Kodik77rus/health-check/internal/app/pkg/env"
	"github.com/Kodik77rus/health-check/internal/app/pkg/postgres"
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

	_, err := postgres.InitPostgres(env)
	if err != nil {
		return errors.Wrap(err, "can't init postgres")
	}

	return nil
}
