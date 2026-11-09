package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"

	"mantel/obfs"
)

type config struct {
	Server string `json:"server"`
	Pin    string `json:"pin"`
	Token  string `json:"token"`
}

type event struct {
	Event  string `json:"event"`
	Port   int    `json:"port,omitempty"`
	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

const maxConfigLine = 4096

func main() {
	os.Exit(run(os.Stdin, os.Stdout))
}

func run(stdin io.Reader, stdout io.Writer) int {
	var mu sync.Mutex
	encoder := json.NewEncoder(stdout)
	emit := func(e event) {
		mu.Lock()
		defer mu.Unlock()
		_ = encoder.Encode(e)
	}

	reader := bufio.NewReaderSize(stdin, maxConfigLine)
	line, err := reader.ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		emit(event{Event: "error", Error: "no configuration on stdin"})
		return 2
	}
	cfg, err := parseConfig(line)
	if err != nil {
		emit(event{Event: "error", Error: err.Error()})
		return 2
	}
	relay, err := obfs.ListenRelay("")
	if err != nil {
		emit(event{Event: "error", Error: err.Error()})
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		cancel()
	}()
	emit(event{Event: "listening", Port: relay.Port()})
	relay.Run(ctx, obfs.ClientConfig{Server: cfg.Server, Pin: cfg.Pin, Token: cfg.Token}, func(state obfs.State, err error) {
		e := event{Event: "state", State: string(state)}
		if err != nil {
			e.Reason, e.Error = classify(err), err.Error()
		}
		emit(e)
	})
	return 0
}

func parseConfig(line []byte) (config, error) {
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, errors.New("configuration is not valid JSON")
	}
	server, err := netip.ParseAddrPort(cfg.Server)
	if err != nil || server.Port() == 0 || server.Addr().Zone() != "" || server.Addr().IsUnspecified() {
		return config{}, fmt.Errorf("invalid server %q", cfg.Server)
	}
	if pin, err := base64.StdEncoding.DecodeString(cfg.Pin); err != nil || len(pin) != 32 {
		return config{}, errors.New("invalid pin")
	}
	if len(cfg.Token) == 0 || len(cfg.Token) > 256 || strings.IndexFunc(cfg.Token, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
		return config{}, errors.New("invalid token")
	}
	cfg.Server = server.String()
	return cfg, nil
}

func classify(err error) string {
	switch {
	case errors.Is(err, obfs.ErrRejected):
		return "rejected"
	case strings.Contains(err.Error(), "does not match the pin"):
		return "pin"
	default:
		return "network"
	}
}
