package main

import (
	"log"
	"os"

	"github.com/Kodik77rus/health-check/internal/app/pkg/env"
	"github.com/pkg/errors"
)

func main() {
	if err := start(); err != nil {
		log.Println("main : shutting down", "err: ", err)
		os.Exit(1)
	}
}

func start() error {
	_, err := env.InitEnv()
	if err != nil {
		return errors.Wrap(err, "cannot get env")
	}

	return nil
}
