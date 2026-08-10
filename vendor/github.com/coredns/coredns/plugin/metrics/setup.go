package metrics

import (
	"crypto/tls"
	"net"
	"runtime"
	"sync"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics/vars"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/uniq"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	u        = uniq.New()
	registry = newReg()

	// There is one Go runtime per process, so this is a latch: the first server
	// block to enable runtime_metrics swaps the collector for everyone, and the
	// swap persists across reloads until process restart.
	runtimeMetricsOnce sync.Once
)

// clientAuthTypes maps the client_auth Corefile values to crypto/tls types.
var clientAuthTypes = map[string]tls.ClientAuthType{
	"NoClientCert":               tls.NoClientCert,
	"RequestClientCert":          tls.RequestClientCert,
	"RequireAnyClientCert":       tls.RequireAnyClientCert,
	"VerifyClientCertIfGiven":    tls.VerifyClientCertIfGiven,
	"RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert,
}

func init() { plugin.Register("prometheus", setup) }

func setup(c *caddy.Controller) error {
	m, err := parse(c)
	if err != nil {
		return plugin.Error("prometheus", err)
	}
	m.Reg = registry.getOrSet(m.Addr, m.Reg)

	c.OnStartup(func() error { m.Reg = registry.getOrSet(m.Addr, m.Reg); u.Set(m.Addr, m.OnStartup); return nil })
	c.OnRestartFailed(func() error { m.Reg = registry.getOrSet(m.Addr, m.Reg); u.Set(m.Addr, m.OnStartup); return nil })

	c.OnStartup(func() error { return u.ForEach() })
	c.OnRestartFailed(func() error { return u.ForEach() })

	c.OnStartup(func() error {
		conf := dnsserver.GetConfig(c)
		for _, h := range conf.ListenHosts {
			addrstr := conf.Transport + "://" + net.JoinHostPort(h, conf.Port)
			for _, p := range conf.Handlers() {
				vars.PluginEnabled.WithLabelValues(addrstr, conf.Zone, conf.ViewName, p.Name()).Set(1)
			}
		}
		return nil
	})
	c.OnRestartFailed(func() error {
		conf := dnsserver.GetConfig(c)
		for _, h := range conf.ListenHosts {
			addrstr := conf.Transport + "://" + net.JoinHostPort(h, conf.Port)
			for _, p := range conf.Handlers() {
				vars.PluginEnabled.WithLabelValues(addrstr, conf.Zone, conf.ViewName, p.Name()).Set(1)
			}
		}
		return nil
	})

	c.OnRestart(m.OnRestart)
	c.OnRestart(func() error { vars.PluginEnabled.Reset(); return nil })
	c.OnFinalShutdown(m.OnFinalShutdown)

	// Initialize metrics.
	buildInfo.WithLabelValues(coremain.CoreVersion, coremain.GitCommit, runtime.Version()).Set(1)

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		m.Next = next
		return m
	})

	return nil
}

func parse(c *caddy.Controller) (*Metrics, error) {
	met := New(defaultAddr)

	i := 0
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		zones := plugin.OriginsFromArgsOrServerBlock(nil /* args */, c.ServerBlockKeys)
		for _, z := range zones {
			met.AddZone(z)
		}
		args := c.RemainingArgs()

		switch len(args) {
		case 0:
		case 1:
			met.Addr = args[0]
			_, _, e := net.SplitHostPort(met.Addr)
			if e != nil {
				return met, e
			}
		default:
			return met, c.ArgErr()
		}

		var (
			clientAuth    tls.ClientAuthType
			clientAuthSet bool
		)
		for c.NextBlock() {
			switch c.Val() {
			case "runtime_metrics":
				if len(c.RemainingArgs()) != 0 {
					return nil, c.ArgErr()
				}
				runtimeMetricsOnce.Do(func() {
					prometheus.Unregister(collectors.NewGoCollector())
					prometheus.MustRegister(collectors.NewGoCollector(
						collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll),
					))
				})
			case "tls":
				if met.tlsConfigPath != "" || met.tlsConfig != nil {
					return nil, c.Err("tls already specified")
				}

				args := c.RemainingArgs()
				switch len(args) {
				case 1:
					// Single argument: exporter-toolkit web config YAML file.
					met.tlsConfigPath = args[0]
				case 2, 3:
					// Inline cert, key and optional CA.
					tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
					if err != nil {
						return nil, err
					}
					met.tlsConfig = tlsConfig
				default:
					return nil, c.ArgErr()
				}
			case "client_auth":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				authType, ok := clientAuthTypes[args[0]]
				if !ok {
					return nil, c.Errf("unknown client_auth type: %s", args[0])
				}
				clientAuth = authType
				clientAuthSet = true
			default:
				return nil, c.Errf("unknown option: %s", c.Val())
			}
		}

		if clientAuthSet {
			if met.tlsConfig == nil {
				return nil, c.Err("client_auth requires an inline tls cert and key")
			}
			met.tlsConfig.ClientAuth = clientAuth
			// Reuse the configured CA (if any) to verify client certificates.
			if met.tlsConfig.RootCAs != nil {
				met.tlsConfig.ClientCAs = met.tlsConfig.RootCAs
			}
		}
	}
	return met, nil
}

// defaultAddr is the address the where the metrics are exported by default.
const defaultAddr = "localhost:9153"
