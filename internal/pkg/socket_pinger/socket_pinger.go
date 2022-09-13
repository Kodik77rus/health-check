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

var (
	syncHostErr              = errors.New("host not sync")
	unsupportedPacketTypeErr = errors.New("unsupported packet type")
	notSockaddrInet6Err      = errors.New("not sockaddrInet6")
	notSockaddrInet4Err      = errors.New("not sockaddrInet4")
)

type SocketPinger struct {
	socketFd   int
	myIPv6     net.IP
	myIPv4     net.IP
	myByteIpv4 [4]byte
	myByteIpv6 [16]byte
	tv         *syscall.Timeval
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
		myIPv4:     ipv4,
		myIPv6:     ipv6,
		myByteIpv4: myIpv4.As4(),
		myByteIpv6: myIpv6.As16(),
		tv:         &tv,
	}, nil
}

func (s *SocketPinger) Ping(host models.Host) error {
	syscall.ForkLock.RLock()
	if err := s.createSocket(host.IsIpv6); err != nil {
		return err
	}
	defer s.closeSocket()
	syscall.ForkLock.RUnlock()

	if err := s.bindSocket(host.IsIpv6); err != nil {
		return err
	}

	remoteAddr, err := buildRemoteSockInetAddr(host)
	if err != nil {
		return err
	}

	tcpSynPacket, err := s.buildSYNPacket(host)
	if err != nil {
		return err
	}

	if err := s.sendWithTimeout(
		remoteAddr,
		tcpSynPacket,
		host.IsIpv6,
	); err != nil {
		return err
	}

	msg, err := s.read()
	if err != nil {
		return err
	}

	TCPpacket, err := decodeTCPPacket(msg)
	if err != nil {
		return errors.Wrap(err, "failed tcp pocket")
	}

	return checkSync(TCPpacket)
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

func (s *SocketPinger) bindSocket(Ipv6 bool) error {
	if Ipv6 {
		return syscall.Bind(s.socketFd, &syscall.SockaddrInet6{
			Port: 0,
			Addr: s.myByteIpv6,
		})
	}
	return syscall.Bind(s.socketFd, &syscall.SockaddrInet4{
		Port: 0,
		Addr: s.myByteIpv4,
	})
}

func (s *SocketPinger) buildSYNPacket(host models.Host) ([]byte, error) {
	var (
		ethL layers.Ethernet
		tcL  layers.TCP
		ipL  gopacket.SerializableLayer
	)

	socketAddr, err := syscall.Getsockname(s.socketFd)
	if err != nil {
		return nil, err
	}

	if host.IsIpv6 {
		sockAddr, ok := socketAddr.(*syscall.SockaddrInet6)
		if !ok {
			return nil, notSockaddrInet6Err
		}
		ethL = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipL = &layers.IPv6{
			SrcIP: s.myIPv6,
			DstIP: host.IP,
		}
		tcL = layers.TCP{
			SrcPort: layers.TCPPort(sockAddr.Port),
			DstPort: layers.TCPPort(host.Port),
		}
	} else {
		sockAddr, ok := socketAddr.(*syscall.SockaddrInet4)
		if !ok {
			return nil, notSockaddrInet4Err
		}
		ethL = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipL = &layers.IPv4{
			SrcIP: s.myIPv4,
			DstIP: host.IP,
		}
		tcL = layers.TCP{
			SrcPort: layers.TCPPort(sockAddr.Port),
			DstPort: layers.TCPPort(host.Port),
		}
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&ethL,
		ipL,
		&tcL,
	)
	return buffer.Bytes(), nil
}

func (s *SocketPinger) sendWithTimeout(remoteSockAddr syscall.Sockaddr, tcpPacket []byte, Ipv6 bool) error {
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

func (s *SocketPinger) closeSocket() error {
	return syscall.Close(s.socketFd)
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

func buildRemoteSockInetAddr(host models.Host) (syscall.Sockaddr, error) {
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

func createInet6TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func createInet4TcpSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

func decodeTCPPacket(packetData []byte) (*layers.TCP, error) {
	packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Lazy)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, unsupportedPacketTypeErr
		}
		return tcp, nil
	}
	return nil, unsupportedPacketTypeErr
}

func checkSync(tcp *layers.TCP) error {
	if tcp.SYN && tcp.ACK {
		return nil
	}
	return syncHostErr
}
