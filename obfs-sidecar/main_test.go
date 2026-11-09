package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"mantel/obfs"
)

type tokens map[string]bool

func (t tokens) Has(hash string) bool { return t[hash] }

const testToken = "device-token-1"

func node(t *testing.T) (addr, pin string) {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	keyPEM, err := obfs.GenerateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	key, err := obfs.ParseKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err = obfs.PinOfPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := obfs.NewServer(obfs.ServerConfig{Key: key, Tokens: tokens{obfs.TokenHash(testToken): true}, Upstream: echo.LocalAddr().String()})
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

func sidecar(t *testing.T, server string) (stdin io.WriteCloser, events <-chan event, done <-chan int) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	codes := make(chan int, 1)
	go func() {
		codes <- run(inR, outW)
		outW.Close()
	}()
	lines := make(chan event, 64)
	go func() {
		scanner := bufio.NewScanner(outR)
		for scanner.Scan() {
			var e event
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				t.Errorf("not a JSON line: %q", scanner.Text())
			}
			lines <- e
		}
		close(lines)
	}()
	if _, err := io.WriteString(inW, server+"\n"); err != nil {
		t.Fatal(err)
	}
	return inW, lines, codes
}

func waitFor(t *testing.T, events <-chan event, match func(event) bool) event {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-events:
			if !ok {
				t.Fatal("sidecar ended early")
			}
			if match(e) {
				return e
			}
		case <-timeout:
			t.Fatal("timed out waiting for an event")
		}
	}
}

func configLine(server, pin, token string) string {
	return fmt.Sprintf(`{"server":%q,"pin":%q,"token":%q}`, server, pin, token)
}

func TestRelaysWireGuardThroughTheNodeAndStopsWithStdin(t *testing.T) {
	addr, pin := node(t)
	stdin, events, done := sidecar(t, configLine(addr, pin, testToken))
	listening := waitFor(t, events, func(e event) bool { return e.Event == "listening" })
	if listening.Port < 1 {
		t.Fatalf("listening without port: %+v", listening)
	}
	waitFor(t, events, func(e event) bool { return e.Event == "state" && e.State == "connected" })

	wg, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listening.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	buf := make([]byte, 2048)
	payload := bytes.Repeat([]byte{0x42}, 1420)
	var n int
	for attempt := 0; attempt < 20; attempt++ {
		_, _ = wg.Write(payload)
		_ = wg.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if n, err = wg.Read(buf); err == nil {
			break
		}
	}
	if err != nil || !bytes.Equal(buf[:n], append([]byte("echo:"), payload...)) {
		t.Fatalf("no echo through the relay: %v", err)
	}

	stdin.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar did not stop after stdin closed")
	}
}

func TestReportsRejectionAndPinMismatch(t *testing.T) {
	addr, pin := node(t)
	otherPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, tc := range []struct{ pin, token, reason string }{
		{pin, "unknown-token", "rejected"},
		{otherPin, testToken, "pin"},
	} {
		stdin, events, done := sidecar(t, configLine(addr, tc.pin, tc.token))
		retry := waitFor(t, events, func(e event) bool { return e.Event == "state" && e.State == "retrying" })
		if retry.Reason != tc.reason {
			t.Errorf("token %q: reason %q, want %q (%s)", tc.token, retry.Reason, tc.reason, retry.Error)
		}
		if strings.Contains(retry.Error, tc.token) {
			t.Errorf("token leaked into the event: %q", retry.Error)
		}
		stdin.Close()
		<-done
	}
}

func TestRejectsBadConfiguration(t *testing.T) {
	pin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, line := range []string{
		``,
		`not json`,
		configLine("node.example:443", pin, "t"),
		configLine("0.0.0.0:443", pin, "t"),
		configLine("203.0.113.7:0", pin, "t"),
		configLine("203.0.113.7:443", "c2hvcnQ=", "t"),
		configLine("203.0.113.7:443", pin, "a b"),
		configLine("203.0.113.7:443", pin, "t\r\nX-Evil: 1"),
		`{"server":"203.0.113.7:443","pin":"` + pin + `","token":"t","extra":1}`,
	} {
		var out bytes.Buffer
		if code := run(strings.NewReader(line+"\n"), &out); code != 2 {
			t.Errorf("%q: exit %d, want 2", line, code)
		}
		if !strings.Contains(out.String(), `"event":"error"`) {
			t.Errorf("%q: no error event: %q", line, out.String())
		}
	}
	if _, err := parseConfig([]byte(configLine("[2001:db8::1]:443", pin, "ok"))); err != nil {
		t.Errorf("IPv6 server refused: %v", err)
	}
}
