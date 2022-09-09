package docker_stats

import (
	"context"
	"os/exec"
	"time"

	"github.com/Kodik77rus/health-check/internal/pkg/utils"
)

const dockerStatComand = "docker ps -a --format \"{{json .}}\" | jq -s"

type ContainerInfo struct {
	ID           string `json:"ID"`
	Name         string `json:"Names"`
	Image        string `json:"Image"`
	State        string `json:"State"`
	Status       string `json:"Status"`
	RunningFor   string `json:"RunningFor"`
	Size         string `json:"Size"`
	Networks     string `json:"Networks"`
	Ports        string `json:"Ports"`
	Command      string `json:"Command"`
	Labels       string `json:"Labels"`
	LocalVolumes string `json:"LocalVolumes"`
	Mounts       string `json:"Mounts"`
	CreatedAt    string `json:"CreatedAt"`
}

type DockerStat struct{}

func (d DockerStat) GetContainersInfo() ([]*ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"bash",
		"-c",
		dockerStatComand,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var conrainersInfo []*ContainerInfo

	if err := utils.JsonDecode(stdout, &conrainersInfo); err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return conrainersInfo, nil
}
