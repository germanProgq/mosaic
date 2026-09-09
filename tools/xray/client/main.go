// xray-health is a developer-only, outbound-only preservation probe.
// It uses the established Xray engine, creates no inbounds/listeners, and never
// changes the existing client application or production Xray configuration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

type Config struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	ID             string `json:"id"`
	Flow           string `json:"flow"`
	ServerName     string `json:"server_name"`
	PublicKey      string `json:"public_key"`
	ShortID        string `json:"short_id"`
	ExpectedEgress string `json:"expected_egress"`
	ConfigPath     string `json:"xray_config_path"`
	ConfigHash     string `json:"xray_config_sha256"`
	Service        string `json:"service"`
	XrayVersion    string `json:"xray_version"`
}

type redactedLogger struct{}

func (redactedLogger) Handle(message xlog.Message) {
	text := regexp.MustCompile(`[A-Za-z0-9_-]{32,}`).ReplaceAllString(message.String(), "[REDACTED]")
	if len(text) > 1500 {
		text = text[:1500]
	}
	fmt.Fprintln(os.Stderr, text)
}
func fail(id string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "id": id})
	os.Exit(1)
}
func main() {
	diagnostic := flag.Bool("diagnostic", false, "emit redacted engine diagnostics to stderr")
	path := flag.String("config", "", "owner-only prepared representative client configuration")
	count := flag.Int("count", 1, "number of scheduled probes (1..1000)")
	interval := flag.Duration("interval", 5*time.Second, "minimum five-second interval")
	flag.Parse()
	if *count < 1 || *count > 1000 || *interval < 5*time.Second || *path == "" {
		fail("arguments")
	}
	var file *os.File
	var err error
	if *path == "-" {
		file = os.Stdin
	} else {
		file, err = os.Open(*path)
		if err != nil {
			fail("config.open")
		}
		stat, statErr := file.Stat()
		if statErr != nil || !stat.Mode().IsRegular() || stat.Size() > 65536 || stat.Mode().Perm()&0077 != 0 {
			fail("config.permissions_or_size")
		}
	}
	var c Config
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		fail("config.schema")
	}
	file.Close()
	if net.ParseIP(c.Server) == nil || net.ParseIP(c.ExpectedEgress) == nil || c.Port != 443 || c.ID == "" || c.PublicKey == "" || c.ServerName == "" {
		fail("config.values")
	}
	cfg := map[string]any{
		"log":      map[string]any{"loglevel": "none"},
		"inbounds": []any{},
		"outbounds": []any{map[string]any{
			"protocol": "vless", "tag": "existing-xray-client",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": c.Server, "port": c.Port, "users": []any{map[string]any{"id": c.ID, "encryption": "none", "flow": c.Flow}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": c.ServerName, "fingerprint": "chrome", "publicKey": c.PublicKey, "shortId": c.ShortID, "spiderX": "/"}},
		}},
	}
	data, _ := json.Marshal(cfg)
	instance, err := core.StartInstance("json", data)
	if err != nil {
		fail("xray.initialize")
	}
	defer instance.Close()
	if *diagnostic {
		xlog.RegisterHandler(redactedLogger{})
	}
	transport := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "api.ipify.org:443" {
				return nil, fmt.Errorf("destination forbidden")
			}
			return core.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("api.ipify.org"), 443))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect forbidden") }}
	start := time.Now()
	failures := 0
	anyFailure := false
	for i := 0; i < *count; i++ {
		scheduled := start.Add(time.Duration(i) * (*interval))
		if delay := time.Until(scheduled); delay > 0 {
			time.Sleep(delay)
		}
		t := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org/", nil)
		response, err := client.Do(req)
		ok := false
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 65))
			response.Body.Close()
			ok = readErr == nil && response.StatusCode == 200 && len(body) <= 64 && strings.TrimSpace(string(body)) == c.ExpectedEgress
		}
		cancel()
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
			anyFailure = true
		} else {
			failures = 0
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": status, "id": "xray.https_verified_egress", "server": c.Server, "sequence": i + 1, "unix_ms": t.UnixMilli(), "duration_ms": float64(time.Since(t).Microseconds()) / 1000, "scheduled_lag_ms": float64(t.Sub(scheduled).Microseconds()) / 1000, "expected_egress_matched": ok})
		if failures >= 2 {
			os.Exit(1)
		}
	}
	if anyFailure {
		os.Exit(1)
	}
}
