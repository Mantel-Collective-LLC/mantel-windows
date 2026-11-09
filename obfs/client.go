package obfs

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRejected = errors.New("obfs: server rejected the tunnel")

type ClientConfig struct {
	Server string
	Pin    string
	Token  string
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

const dialTimeout = 15 * time.Second

type Conn struct {
	conn   net.Conn
	reader *bufio.Reader
	wmu    sync.Mutex
}

func Dial(ctx context.Context, config ClientConfig) (*Conn, error) {
	if config.Server == "" || config.Pin == "" || config.Token == "" {
		return nil, errors.New("obfs: server, pin and token are required")
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	dial := config.Dial
	if dial == nil {
		dial = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	raw, err := dial(ctx, "tcp", config.Server)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(config.Server)
	tlsConn := tls.Client(raw, clientTLS(config.Pin))
	deadline, _ := ctx.Deadline()
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nAuthorization: Bearer %s\r\n\r\n",
		hostHeader(host), UpgradeProto, config.Token)
	if _, err := tlsConn.Write([]byte(request)); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	reader := bufio.NewReaderSize(tlsConn, MaxFrame+2)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = tlsConn.Close()
		return nil, ErrRejected
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return &Conn{conn: tlsConn, reader: reader}, nil
}

func clientTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("obfs: no server certificate")
			}
			if got := Pin(state.PeerCertificates[0]); !pinEqual(got, pin) {
				return pinMismatch(got)
			}
			return nil
		},
	}
}

func hostHeader(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func (c *Conn) ReadPacket(buf []byte) (int, error) { return ReadFrame(c.reader, buf) }

func (c *Conn) WritePacket(packet []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return WriteFrame(c.conn, packet)
}

func (c *Conn) Close() error { return c.conn.Close() }

type State string

const (
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateRetrying   State = "retrying"
)

type Relay struct {
	udp *net.UDPConn
}

func ListenRelay(address string) (*Relay, error) {
	if address == "" {
		address = "127.0.0.1:0"
	}
	local, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	if !local.IP.IsLoopback() {
		return nil, errors.New("obfs: relay must listen on loopback")
	}
	udp, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	return &Relay{udp: udp}, nil
}

func (r *Relay) Port() int { return r.udp.LocalAddr().(*net.UDPAddr).Port }

func (r *Relay) Run(ctx context.Context, config ClientConfig, onState func(State, error)) {
	if onState == nil {
		onState = func(State, error) {}
	}
	var current atomic.Pointer[Conn]
	var peer atomic.Pointer[net.UDPAddr]
	stop := context.AfterFunc(ctx, func() {
		_ = r.udp.Close()
		if c := current.Load(); c != nil {
			_ = c.Close()
		}
	})
	defer stop()
	go func() {
		buf := make([]byte, MaxFrame)
		for {
			n, from, err := r.udp.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if !from.IP.IsLoopback() {
				continue
			}
			peer.Store(from)
			if c := current.Load(); c != nil {
				_ = c.WritePacket(buf[:n])
			}
		}
	}()
	backoff := time.Second
	onState(StateConnecting, nil)
	buf := make([]byte, MaxFrame)
	for ctx.Err() == nil {
		conn, err := Dial(ctx, config)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			onState(StateRetrying, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		current.Store(conn)
		if ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		onState(StateConnected, nil)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				break
			}
			if to := peer.Load(); to != nil {
				_, _ = r.udp.WriteToUDP(buf[:n], to)
			}
		}
		current.Store(nil)
		_ = conn.Close()
		if ctx.Err() == nil {
			onState(StateRetrying, errors.New("obfs: connection closed"))
		}
	}
}

func Probe(ctx context.Context, address, pin string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, clientTLS(pin))
	defer conn.Close()
	return conn.HandshakeContext(ctx)
}
