package obfs

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxFrame       = 16384
	MaxConns       = 1024
	TunnelIdle     = 3 * time.Minute
	headerTimeout  = 10 * time.Second
	keepAliveIdle  = 60 * time.Second
	writeTimeout   = 30 * time.Second
	maxHeaderBytes = 8 << 10
	maxTokenLength = 256
)

type TokenSet interface{ Has(hash string) bool }

type ServerConfig struct {
	Key      *ecdsa.PrivateKey
	Tokens   TokenSet
	Upstream string
}

type Server struct {
	config ServerConfig
	http   *http.Server
	active atomic.Int64
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Key == nil || config.Tokens == nil || config.Upstream == "" {
		return nil, errors.New("obfs: key, tokens and upstream are required")
	}
	cert, err := selfSigned(config.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{config: config}
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       keepAliveIdle,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	return s, nil
}

func (s *Server) Serve(listener net.Listener) error {
	return s.http.ServeTLS(&limitListener{Listener: listener, server: s}, "", "")
}

func (s *Server) Close() error { return s.http.Close() }

func (s *Server) Active() int64 { return s.active.Load() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 || !strings.EqualFold(r.Header.Get("Upgrade"), UpgradeProto) || !headerHasToken(r.Header, "Connection", "upgrade") || !s.authorized(r) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+UpgradeProto+"\r\n\r\n"); err != nil {
		return
	}
	s.relay(conn, buffered.Reader)
}

func (s *Server) authorized(r *http.Request) bool {
	value := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(value, "Bearer ")
	if !ok || token == "" || len(token) > maxTokenLength {
		return false
	}
	return s.config.Tokens.Has(TokenHash(token))
}

func (s *Server) relay(conn net.Conn, reader *bufio.Reader) {
	udp, err := net.Dial("udp", s.config.Upstream)
	if err != nil {
		return
	}
	var closing atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, MaxFrame)
		for {
			n, err := udp.Read(buf)
			if err != nil {
				if closing.Load() || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if WriteFrame(conn, buf[:n]) != nil {
				_ = conn.Close()
				return
			}
		}
	}()
	buf := make([]byte, MaxFrame)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(TunnelIdle))
		n, err := ReadFrame(reader, buf)
		if err != nil {
			break
		}
		_, _ = udp.Write(buf[:n])
	}
	closing.Store(true)
	_ = udp.Close()
	<-done
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

type limitListener struct {
	net.Listener
	server *Server
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.server.active.Add(1) > MaxConns {
			l.server.active.Add(-1)
			_ = conn.Close()
			continue
		}
		return &countedConn{Conn: conn, active: &l.server.active}, nil
	}
}

type countedConn struct {
	net.Conn
	active *atomic.Int64
	once   sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.active.Add(-1) })
	return c.Conn.Close()
}

func selfSigned(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func GenerateKeyPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("obfs: no PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("obfs: key is not ECDSA P-256")
	}
	return key, nil
}

type FileTokens struct {
	Path string

	mu      sync.Mutex
	set     map[string]bool
	modTime time.Time
	size    int64
	checked time.Time
}

func (f *FileTokens) Has(hash string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now := time.Now(); now.Sub(f.checked) >= time.Second {
		f.checked = now
		f.reload()
	}
	return f.set[hash]
}

func (f *FileTokens) reload() {
	info, err := os.Stat(f.Path)
	if err != nil || (info.ModTime().Equal(f.modTime) && info.Size() == f.size && f.set != nil) {
		return
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return
	}
	set := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line = strings.TrimSpace(line); ValidTokenHash(line) {
			set[line] = true
		}
	}
	f.set, f.modTime, f.size = set, info.ModTime(), info.Size()
}

func (f *FileTokens) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reload()
	return len(f.set)
}
