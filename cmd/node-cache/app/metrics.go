/*
Copyright 2021 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/reuseport"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/uniq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/exporter-toolkit/web"
)

var (
	log = clog.NewWithPlugin("prometheus")
	u   = uniq.New()

	// ListenAddr is assigned the address of the prometheus listener. Its use
	// is mainly in tests where we listen on "localhost:0" and need to retrieve
	// the actual address.
	ListenAddr string
)

// shutdownTimeout is the maximum amount of time the metrics plugin will wait
// before erroring when it tries to close the metrics server
const shutdownTimeout time.Duration = time.Second * 5

var setupErrCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "nodecache",
	Name:      "setup_errors_total",
	Help:      "The number of errors during periodic network setup for node-cache",
}, []string{"errortype"})

// startupListener wraps a net.Listener to detect when Accept() is first called
type startupListener struct {
	net.Listener
	readyOnce sync.Once
	ready     chan struct{}
}

func newStartupListener(l net.Listener) *startupListener {
	return &startupListener{
		Listener: l,
		ready:    make(chan struct{}),
	}
}

func (sl *startupListener) Accept() (net.Conn, error) {
	// Signal ready on first Accept() call (server is running)
	sl.readyOnce.Do(func() {
		close(sl.ready)
	})
	return sl.Listener.Accept()
}

func (sl *startupListener) Ready() <-chan struct{} {
	return sl.ready
}

// Metrics holds the prometheus configuration. The metrics' path is fixed to be /metrics .
type Metrics struct {
	Next plugin.Handler
	Addr string
	Reg  *prometheus.Registry

	ln      net.Listener
	lnSetup bool

	mux *http.ServeMux
	srv *http.Server

	tlsConfig *tlsConfig
}

// tlsConfig is the TLS configuration for Metrics
type tlsConfig struct {
	// Enabled controls whether TLS is active
	// Optional: Defaults to true when tls block is present
	Enabled bool

	// CertFile is the path to the server's certificate file in PEM format
	// Required when TLS is enabled
	CertFile string

	// KeyFile is the path to the server's private key file in PEM format
	// Required when TLS is enabled
	KeyFile string

	// ClientCAFile is the path to the CA certificate file for client verification
	// Optional: Only needed for client authentication
	// Default: No client verification
	// Can contain multiple CA certificates in a single PEM file
	ClientCAFile string

	// MinVersion is the minimum TLS version to accept
	// Optional: Defaults to tls.VersionTLS13
	// Possible values: tls.VersionTLS10 through tls.VersionTLS13
	MinVersion string

	// ClientAuthType controls how client certificates are handled
	// Optional: Defaults to "RequestClientCert" (strictest)
	// Possible values:
	//  - "RequestClientCert"
	//  - "RequireAnyClientCert"
	//  - "VerifyClientCertIfGiven"
	//  - "RequireAndVerifyClientCert"
	//  - "NoClientCert"
	ClientAuthType string
}

// New returns a new instance of Metrics with the given address.
func New(addr string, cfg *tlsConfig) *Metrics {
	met := &Metrics{
		Addr:      addr,
		Reg:       prometheus.DefaultRegisterer.(*prometheus.Registry),
		tlsConfig: cfg,
	}

	return met
}

// validate validates the Metrics configuration
func (m *Metrics) validate() error {
	if m.tlsConfig != nil && m.tlsConfig.Enabled {
		if m.tlsConfig.CertFile == "" {
			return fmt.Errorf("TLS enabled but no certificate file specified")
		}
		if m.tlsConfig.KeyFile == "" {
			return fmt.Errorf("TLS enabled but no key file specified")
		}
		// Check if files exist
		if _, err := os.Stat(m.tlsConfig.CertFile); err != nil {
			return fmt.Errorf("certificate file not found: %s", m.tlsConfig.CertFile)
		}
		if _, err := os.Stat(m.tlsConfig.KeyFile); err != nil {
			return fmt.Errorf("key file not found: %s", m.tlsConfig.KeyFile)
		}
		// Check that minversion is proper
		allowedVersion := []string{"TLS10", "TLS11", "TLS12", "TLS13"}
		if !slices.Contains(allowedVersion, m.tlsConfig.MinVersion) {
			return fmt.Errorf("min TLS version must be one of: %s", strings.Join(allowedVersion, ", "))
		}
	}
	return nil
}

// OnStartup sets up the metrics on startup.
func (m *Metrics) OnStartup() error {
	if err := m.validate(); err != nil {
		return err
	}

	ln, err := reuseport.Listen("tcp", m.Addr)
	if err != nil {
		log.Errorf("Failed to start metrics listener: %s", err)
		return err
	}

	startupListener := newStartupListener(ln)
	m.ln = startupListener
	m.lnSetup = true

	m.mux = http.NewServeMux()
	m.mux.Handle("/metrics", promhttp.HandlerFor(m.Reg, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:    m.Addr,
		Handler: m.mux,
	}
	m.srv = server

	// Create logger for the server
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	webConfig := &web.FlagConfig{
		WebListenAddresses: &[]string{m.Addr},
		WebSystemdSocket:   new(bool), // false by default
		WebConfigFile:      new(string),
	}

	tlsEnabled := m.tlsConfig != nil && m.tlsConfig.Enabled
	if tlsEnabled {
		configFile, err := m.getHTTPSWebConfigFile()
		if err != nil {
			return fmt.Errorf("failed to create WebConfigFile for HTTPS: %w", err)
		}
		*webConfig.WebConfigFile = configFile
	} else {
		// Setting WebConfigFile to empty disables TLS
		*webConfig.WebConfigFile = ""
	}

	// Create channel to signal when server is ready
	errChan := make(chan error, 1)
	go func() {
		// Try to start the server and report result if there is an error.
		// web.Serve() never returns nil, it always returns a non-nil error and
		// it doesn't return anything if server starts successfully.
		// startupListener handles capturing succesful startup.
		err := web.Serve(startupListener, m.srv, webConfig, logger)
		if err != nil {
			errChan <- err
		}
	}()

	// Wait for server to be ready or error
	select {
	case <-startupListener.Ready():
		// Server started successfully
		clog.Infof("Nodecache metrics are served at %s with TLS set to %v", m.Addr, tlsEnabled)
	case err := <-errChan:
		clog.Errorf("Failed to start metrics server with TLS set to %v: %v", tlsEnabled, err)
		return err
	case <-time.After(2 * time.Second):
		return fmt.Errorf("timeout waiting for server to start")
	}

	registerMetrics()
	ListenAddr = ln.Addr().String() // For tests.
	return nil
}

func (m *Metrics) getHTTPSWebConfigFile() (string, error) {
	// Create temporary YAML config file for TLS settings
	tmpFile, err := os.CreateTemp("", "metrics-tls-config-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary TLS config file: %w", err)
	}
	defer tmpFile.Close()

	yamlConfig := fmt.Sprintf(`
tls_server_config:
  cert_file: %s
  key_file: %s
  client_ca_file: %s
  client_auth_type: %s
  min_version: %s
`, m.tlsConfig.CertFile, m.tlsConfig.KeyFile, m.tlsConfig.ClientCAFile, m.tlsConfig.ClientAuthType, m.tlsConfig.MinVersion)

	if _, err := tmpFile.WriteString(yamlConfig); err != nil {
		return "", fmt.Errorf("failed to write TLS config to temporary file: %w", err)
	}

	return tmpFile.Name(), nil
}

// OnRestart stops the listener on reload.
func (m *Metrics) OnRestart() error {
	if !m.lnSetup {
		return nil
	}
	u.Unset(m.Addr)
	return m.stopServer()
}

func (m *Metrics) stopServer() error {
	if !m.lnSetup {
		return nil
	}
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	// Shutdown also closes listeners
	if err := m.srv.Shutdown(ctx); err != nil {
		log.Infof("Failed to stop metrics server: %s", err)
		return err
	}

	m.lnSetup = false
	prometheus.Unregister(setupErrCount)
	return nil
}

// OnFinalShutdown tears down the metrics listener on shutdown and restart.
func (m *Metrics) OnFinalShutdown() error { return m.stopServer() }

func publishErrorMetric(label string) {
	setupErrCount.WithLabelValues(label).Inc()
}

func registerMetrics() {
	prometheus.MustRegister(setupErrCount)
	setupErrCount.WithLabelValues("iptables").Add(0)
	setupErrCount.WithLabelValues("iptables_lock").Add(0)
	setupErrCount.WithLabelValues("interface_add").Add(0)
	setupErrCount.WithLabelValues("interface_check").Add(0)
	setupErrCount.WithLabelValues("configmap").Add(0)
}
