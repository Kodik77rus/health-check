package socket_pinger

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/Kodik77rus/health-check/internal/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	badIp = errors.New("badIp")
)

type SocketPinger struct {
	MyIPv6 net.IP
	MyIPv4 net.IP
}

func InitSocketPinger() (*SocketPinger, error) {
	ipv4, ipv6, err := getInternalIPs()
	if err != nil {
		return nil, err
	}

	return &SocketPinger{
		MyIPv4: ipv4,
		MyIPv6: ipv6,
	}, nil
}

func (s *SocketPinger) Ping(host models.Host) error {
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

		synPacket, err := s.builSYNTcpPacket(host)
		if err != nil {
			errChan <- err
			return
		}

		_, err = syscall.Write(socket, synPacket)
		if err != nil {
			errChan <- err
			return
		}

		buff := make([]byte, 1024)
		msg, err := syscall.Read(socket, buff)
		if err != nil {
			errChan <- err
			return
		}
		fmt.Printf("% X\n", string(buff[0:msg]))
		errChan <- nil
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

func (s *SocketPinger) builSYNTcpPacket(host models.Host) ([]byte, error) {
	var ipLayer gopacket.SerializableLayer

	if host.IsIpv6 {
		ipLayer = &layers.IPv6{
			SrcIP:      s.MyIPv6,
			DstIP:      host.IP,
			NextHeader: layers.IPProtocolTCP,
		}
	} else {
		ipLayer = &layers.IPv4{
			SrcIP:    s.MyIPv4,
			DstIP:    host.IP,
			Protocol: layers.IPProtocolTCP,
		}
	}

	tcpLayer := layers.TCP{
		DstPort: layers.TCPPort(host.Port),
		SYN:     true,
	}

	// tcpLayer.SetNetworkLayerForChecksum(gopacket.SerializableLayer(ipLayer))

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{}

	err := gopacket.SerializeLayers(buf, opts, ipLayer, &tcpLayer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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
	return syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func createInet4TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func getInternalIPs() (net.IP, net.IP, error) {
	itf, _ := net.InterfaceByName("eno1") //here your interface
	item, _ := itf.Addrs()
	var ipv4 net.IP
	var ipv6 net.IP
	for _, addr := range item {
		switch v := addr.(type) {
		case *net.IPNet:
			if !v.IP.IsLoopback() {
				if v.IP.To4() != nil {
					ipv4 = v.IP
				}
				if v.IP.To16() != nil {
					ipv6 = v.IP
				}
			}
		}
	}
	if ipv4 != nil && ipv6 != nil {
		return ipv4, ipv6, nil
	}
	return nil, nil, errors.New("Can't load nternal IPs")
}
