package obfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type staticTokens map[string]bool

func (s staticTokens) Has(hash string) bool { return s[hash] }

const testToken = "device-token-1"

func udpEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return conn.LocalAddr().String()
}

func startServer(t *testing.T) (addr, pin string) {
	t.Helper()
	keyPEM, err := GenerateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err = PinOfPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Key: key, Tokens: staticTokens{TokenHash(testToken): true}, Upstream: udpEcho(t)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String(), pin
}

func TestRelayEndToEnd(t *testing.T) {
	addr, pin := startServer(t)
	relay, err := ListenRelay("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connected := make(chan struct{}, 1)
	go relay.Run(ctx, ClientConfig{Server: addr, Pin: pin, Token: testToken}, func(state State, err error) {
		if state == StateConnected {
			connected <- struct{}{}
		}
	})
	select {
	case <-connected:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not connect")
	}
	wg, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	buf := make([]byte, 2048)
	for i, payload := range [][]byte{[]byte("handshake"), bytes.Repeat([]byte{0xab}, 1452)} {
		var n int
		for attempt := 0; attempt < 20; attempt++ {
			_, _ = wg.Write(payload)
			_ = wg.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			if n, err = wg.Read(buf); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("packet %d: no echo: %v", i, err)
		}
		if want := append([]byte("echo:"), payload...); !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d: got %q", i, buf[:min(n, 32)])
		}
	}
}

func probeClient(h2 bool) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2}
	if !h2 {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport}
}

func TestProbeWithoutTokenGets404(t *testing.T) {
	addr, _ := startServer(t)
	cases := map[string]http.Header{
		"plain":         {},
		"wrong token":   {"Connection": {"Upgrade"}, "Upgrade": {UpgradeProto}, "Authorization": {"Bearer nope"}},
		"no upgrade":    {"Authorization": {"Bearer " + testToken}},
		"wrong upgrade": {"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Authorization": {"Bearer " + testToken}},
	}
	for name, header := range cases {
		request, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		request.Header = header
		response, err := probeClient(false).Do(request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound || len(body) != 0 {
			t.Fatalf("%s: got %d %q", name, response.StatusCode, body)
		}
		if response.Header.Get("Server") != "" || strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "mantel") {
			t.Fatalf("%s: revealing headers %v", name, response.Header)
		}
	}
	response, err := probeClient(true).Get("https://" + addr + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.ProtoMajor != 2 {
		t.Fatalf("h2 probe: %d %s", response.StatusCode, response.Proto)
	}
}

func TestDialRejectsWrongTokenAndPin(t *testing.T) {
	addr, pin := startServer(t)
	if _, err := Dial(context.Background(), ClientConfig{Server: addr, Pin: pin, Token: "other"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong token: %v", err)
	}
	other := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := Dial(context.Background(), ClientConfig{Server: addr, Pin: other, Token: testToken}); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("wrong pin: %v", err)
	}
	conn, err := Dial(context.Background(), ClientConfig{Server: addr, Pin: pin, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestNoSNI(t *testing.T) {
	keyPEM, _ := GenerateKeyPEM()
	key, _ := ParseKeyPEM(keyPEM)
	cert, err := selfSigned(key)
	if err != nil {
		t.Fatal(err)
	}
	sni := make(chan string, 1)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			return nil, nil
		}})
		_ = server.Handshake()
		server.Close()
	}()
	pin, _ := PinOfPublicKey(&key.PublicKey)
	_, _ = Dial(context.Background(), ClientConfig{Server: listener.Addr().String(), Pin: pin, Token: "x"})
	if got := <-sni; got != "" {
		t.Fatalf("SNI sent: %q", got)
	}
}

func TestFrames(t *testing.T) {
	var stream bytes.Buffer
	if err := WriteFrame(&stream, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream.Bytes(), []byte{0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("frame %v", stream.Bytes())
	}
	buf := make([]byte, MaxFrame)
	if n, err := ReadFrame(&stream, buf); err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("read %d %v", n, err)
	}
	if WriteFrame(io.Discard, nil) == nil || WriteFrame(io.Discard, make([]byte, MaxFrame+1)) == nil {
		t.Fatal("empty/oversized frame accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0}), buf); !errors.Is(err, ErrFrame) {
		t.Fatalf("zero frame: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff}), buf); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestFileTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	tokens := &FileTokens{Path: path}
	hash := TokenHash(testToken)
	if tokens.Has(hash) {
		t.Fatal("missing file must know nothing")
	}
	if err := os.WriteFile(path, []byte(hash+"\nnot-a-hash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tokens.checked = time.Time{}
	if !tokens.Has(hash) || tokens.Count() != 1 {
		t.Fatal("hash not loaded")
	}
	_ = os.Remove(path)
	tokens.checked = time.Time{}
	if !tokens.Has(hash) {
		t.Fatal("a vanished file must keep the last set")
	}
	if ValidTokenHash(strings.ToUpper(hash)) || !ValidTokenHash(hash) {
		t.Fatal("ValidTokenHash")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	keyPEM, _ := GenerateKeyPEM()
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := selfSigned(key)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	want, _ := PinOfPublicKey(&key.PublicKey)
	if Pin(parsed) != want {
		t.Fatal("Pin(cert) != PinOfPublicKey")
	}
	if _, err := ParseKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("garbage key accepted")
	}
}

func TestProbe(t *testing.T) {
	addr, pin := startServer(t)
	if err := Probe(context.Background(), addr, pin); err != nil {
		t.Fatal(err)
	}
	if err := Probe(context.Background(), addr, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err == nil {
		t.Fatal("wrong pin accepted")
	}
}
