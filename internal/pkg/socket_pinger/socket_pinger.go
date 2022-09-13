package socket_pinger

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/Kodik77rus/health-check/internal/pkg/env"
	"github.com/Kodik77rus/health-check/internal/pkg/models"
	"github.com/Kodik77rus/health-check/internal/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
)

var notSyncErr = errors.New("host not sync")

type SocketPinger struct {
	socketFd int
	tv       *syscall.Timeval
	myIPv6   [16]byte
	myIPv4   [4]byte
}

func InitSocketPinger(env *env.Env) (*SocketPinger, error) {
	ipv4, ipv6, err := getInternalIPs()
	if err != nil {
		return nil, err
	}
	myIpv4, ok := utils.AddrFromSlice(ipv4)
	if !ok {
		return nil, errors.Errorf("IPv4 slice's length is not 4", ipv4)
	}
	myIpv6, ok := utils.AddrFromSlice(ipv6)
	if !ok {
		return nil, errors.Errorf("IPv6 slice's length is not 16", ipv6)
	}
	tv := syscall.NsecToTimeval(env.PING_TIMEOUT.Nanoseconds())
	return &SocketPinger{
		myIPv4: myIpv6.As4(),
		myIPv6: myIpv4.As16(),
		tv:     &tv,
	}, nil
}

func (s *SocketPinger) Ping(host models.Host) error {
	if err := s.createSocket(host.IsIpv6); err != nil {
		return err
	}
	defer s.closeSocket()

	if err := s.bindSocket(host.IsIpv6); err != nil {
		return err
	}

	remoteAddr, err := initRemoteSockInetAddr(host)
	if err != nil {
		return err
	}

	if err := s.send(
		remoteAddr,
		buildSYNPacket(host),
		host.IsIpv6,
	); err != nil {
		return err
	}

	msg, err := s.read()
	if err != nil {
		return err
	}

	tcpPocket, err := decode(msg)
	if err != nil {
		return err
	}

	return checkSync(tcpPocket)
}

func (s *SocketPinger) createSocket(Ipv6 bool) error {
	var err error

	if Ipv6 {
		s.socketFd, err = createInet6TcpSocket()
		if err != nil {
			return err
		}
		return nil
	}

	s.socketFd, err = createInet4TcpSocket()
	if err != nil {
		return err
	}
	return nil
}

func (s *SocketPinger) closeSocket() error {
	return syscall.Close(s.socketFd)
}

func (s *SocketPinger) bindSocket(Ipv6 bool) error {
	if Ipv6 {
		return syscall.Bind(s.socketFd, &syscall.SockaddrInet6{
			Port: 0,
			Addr: s.myIPv6,
		})
	}
	return syscall.Bind(s.socketFd, &syscall.SockaddrInet4{
		Port: 0,
		Addr: s.myIPv4,
	})
}

func (s *SocketPinger) send(remoteSockAddr syscall.Sockaddr, tcpPacket []byte, Ipv6 bool) error {
	if err := syscall.SetsockoptTimeval(
		s.socketFd,
		syscall.SOL_SOCKET,
		syscall.SO_RCVTIMEO,
		s.tv,
	); err != nil {
		return err
	}
	return syscall.Sendto(s.socketFd, tcpPacket, 0, remoteSockAddr)
}

func (s *SocketPinger) read() ([]byte, error) {
	buf := make([]byte, 512)
	_, _, err := syscall.Recvfrom(s.socketFd, buf, 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func initRemoteSockInetAddr(host models.Host) (syscall.Sockaddr, error) {
	addr, ok := netip.AddrFromSlice(host.IP)
	if !ok {
		return nil, errors.Errorf("remote host IPv6 %v slice's length is not 4 or 16", addr)
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

func getInternalIPs() (net.IP, net.IP, error) {
	var (
		ipv4 net.IP
		ipv6 net.IP
	)

	itf, err := net.InterfaceByName("eno1")
	if err != nil {
		return nil, nil, err
	}

	item, err := itf.Addrs()
	if err != nil {
		return nil, nil, err
	}

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

	return nil, nil, errors.New("Can't load internal IPs")
}

func createInet6TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func createInet4TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func buildSYNPacket(host models.Host) []byte {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.TCP{
			SYN: true,
		},
	)
	return buffer.Bytes()
}

func decode(msg []byte) (layers.TCP, error) {
	var (
		tcp layers.TCP
		df  gopacket.DecodeFeedback
	)
	if err := tcp.DecodeFromBytes(msg, df); err != nil {
		return tcp, err
	}
	return tcp, nil
}

func checkSync(tcp layers.TCP) error {
	if tcp.SYN && tcp.ACK {
		return nil
	}
	return notSyncErr
}
