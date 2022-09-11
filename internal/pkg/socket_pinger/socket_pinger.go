package socket_pinger

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"github.com/Kodik77rus/health-check/internal/pkg/models"
)

var (
	badIp = errors.New("badIp")
)

type SocketPinger struct{}

func (s SocketPinger) Ping(host models.Host) error {
	socket, err := createSocket(host.IsIpv6)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	remoteSockAddr, err := initRemoteSockInetAddr(host)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		defer close(errChan)

		if err := syscall.Connect(socket, remoteSockAddr); err != nil {
			errChan <- err
			return
		}

		_, err := syscall.Write(socket, []byte("yellow"))
		if err != nil {
			errChan <- err
			return
		}

		buff := make([]byte, 1024)
		numRead, err := syscall.Read(socket, buff)
		if err != nil {
			errChan <- err
			return
		}
		fmt.Printf("% X\n", string(buff[0:numRead]))
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			return err
		}
	}
}

func createSocket(Ipv6 bool) (int, error) {
	if Ipv6 {
		return createInet6TcpSocket()
	}
	return createInet4TcpSocket()
}

func initRemoteSockInetAddr(host models.Host) (syscall.Sockaddr, error) {
	addr, ok := netip.AddrFromSlice(host.IP)
	if !ok {
		return nil, badIp
	}

	if host.IsIpv6 {
		return &syscall.SockaddrInet6{
			Port: host.Port,
			Addr: addr.As16(),
		}, nil
	}

	return &syscall.SockaddrInet4{
		Port: host.Port,
		Addr: addr.As4(),
	}, nil
}

func createInet6TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
}

func createInet4TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
}
