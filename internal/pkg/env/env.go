package env

import (
	"os"
	"time"

	"github.com/Kodik77rus/health-check/internal/pkg/utils"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

type Env struct {
	Port int

	Log_LVL string

	Postgres_Host     string
	Postgres_Port     string
	Postgres_User     string
	Postgres_Password string
	Postgres_Dbname   string

	PING_TIMEOUT time.Duration
}

func InitEnv() (*Env, error) {
	_ = godotenv.Load()

	env := Env{}
	var err error

	env.Port, err = getEnvInt("PORT")
	if err != nil {
		return nil, err
	}

	env.Log_LVL, err = getEnv("Log_LVL")
	if err != nil {
		return nil, err
	}

	env.Postgres_Host, err = getEnv("POSTGRES_HOST")
	if err != nil {
		return nil, err
	}

	env.Postgres_Port, err = getEnv("POSTGRES_PORT")
	if err != nil {
		return nil, err
	}

	env.Postgres_User, err = getEnv("POSTGRES_USER")
	if err != nil {
		return nil, err
	}

	env.Postgres_Password, err = getEnv("POSTGRES_PASSWORD")
	if err != nil {
		return nil, err
	}

	env.Postgres_Dbname, err = getEnv("POSTGRES_DATABASE")
	if err != nil {
		return nil, err
	}

	env.PING_TIMEOUT, err = getEnvDuration("PING_TIMEOUT")
	if err != nil {
		return nil, err
	}

	return &env, err
}

func getEnv(path string) (string, error) {
	env := os.Getenv(path)
	if env != "" {
		return env, nil
	}
	return "", errors.Errorf("%s env variable is not defined", path)
}

func getEnvInt(path string) (int, error) {
	env, err := getEnv(path)
	if err != nil {
		return 0, err
	}

	intEnv, err := utils.StrToInt(env)
	if err != nil {
		return 0, errors.Errorf("%s env variable is not int convertible", path)
	}
	return intEnv, nil
}

func getEnvDuration(path string) (time.Duration, error) {
	env, err := getEnv(path)
	if err != nil {
		return 0, err
	}
	durationEnv, err := utils.ParseDuration(env)
	if err != nil {
		return 0, err
	}
	return durationEnv, nil
}
