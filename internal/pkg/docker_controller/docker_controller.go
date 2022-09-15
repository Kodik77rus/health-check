package docker_controller

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"github.com/Kodik77rus/health-check/internal/pkg/utils"
)

type DockerController struct{}

type ContainerInfo struct {
	ID     string   `json:"Id"`
	Name   []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

func (d DockerController) GetContainersInfo() ([]*ContainerInfo, error) {
	var dialer net.Dialer

	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", "/var/run/docker.sock")
			},
		}}

	u := &url.URL{
		Scheme: "http",
		Host:   "health-check",
		Path:   "/v1.41/containers/json",
	}

	header := make(http.Header)
	header.Add("Content-Type", "application/json")

	httpReq := &http.Request{
		Method: "GET",
		URL:    u,
		Header: header,
	}

	resp, err := c.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decodedData, err := utils.Base64Decode(body)
	if err != nil {
		return nil, err
	}

	var dockerContainers []*ContainerInfo

	if err := utils.JsonUnmarshal(decodedData, &dockerContainers); err != nil {
		return nil, err
	}

	return dockerContainers, nil
}
