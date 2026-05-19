package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/digitalocean-labs/ebpf_exporter/collectors"
)

const (
	statsModeDisabled string = "disabled"
	statsModeSample   string = "sample"
	statsModeEnabled  string = "enabled"
)

type listenAddrs []string

func (i *listenAddrs) String() string {
	return strings.Join(*i, ",")
}

func (i *listenAddrs) Set(value string) error {
	_, _, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid listen address value %q: %w", value, err)
	}
	*i = append(*i, value)
	return nil
}

type config struct {
	LogLevel    slog.Level
	logLevelStr string

	ListenAddrs listenAddrs
	MetricsPath string
	SdNotify    bool

	ProgCollector struct {
		Enabled bool
		Stats   struct {
			Mode           string
			SampleInterval time.Duration // how often to enable BPF stats for sampling
			SampleDuration time.Duration // how long to keep BPF stats enabled for
		}
	}
	MapCollector struct {
		Enabled bool
		Config  collectors.MapCollectorConfig
	}
	LinkCollector struct {
		Enabled bool
		Config  collectors.LinkCollectorConfig
	}
	BTFCollector struct {
		Enabled bool
		Config  collectors.BTFCollectorConfig
	}
}

func initConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.logLevelStr, "log-level", slog.LevelInfo.String(), "log level based on slog")

	flag.Var(&cfg.ListenAddrs, "listen-addr",
		"address(es) to listen on for the metrics server")
	flag.StringVar(&cfg.MetricsPath, "metrics-path", "/metrics",
		"HTTP GET path under which the Prometheus metrics are exposed")
	flag.BoolVar(&cfg.SdNotify, "sd-notify", false,
		"enable systemd status notifications")

	flag.BoolVar(&cfg.ProgCollector.Enabled, "collector.prog", true,
		"toggle collection of eBPF program metrics")
	flag.StringVar(&cfg.ProgCollector.Stats.Mode, "prog-stats-mode", statsModeDisabled,
		fmt.Sprintf("Enable stats collection for all running eBPF program (requires Linux 5.8+): %s (default), %s, %s",
			statsModeDisabled, statsModeSample, statsModeEnabled),
	)
	flag.DurationVar(&cfg.ProgCollector.Stats.SampleInterval, "prog-stats-sample-interval", 0,
		"frequency of BPF program stats collection when in sample mode")
	flag.DurationVar(&cfg.ProgCollector.Stats.SampleDuration, "prog-stats-sample-duration", 0,
		"duration of BPF program stats collection when in sample mode")

	flag.BoolVar(&cfg.MapCollector.Enabled, "collector.map", true,
		"toggle collection of eBPF map metrics")
	flag.BoolVar(&cfg.MapCollector.Config.CountEntries, "map-count-entries", false,
		"enable counting of current number entries in all maps")

	flag.BoolVar(&cfg.LinkCollector.Enabled, "collector.link", true,
		"toggle collection of eBPF link metrics")

	flag.BoolVar(&cfg.BTFCollector.Enabled, "collector.btf", true,
		"toggle collection of eBPF BTF metrics")

	flag.Parse()

	// default value, since it's a custom type
	if len(cfg.ListenAddrs) == 0 {
		cfg.ListenAddrs = append(cfg.ListenAddrs, ":11000")
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(cfg.logLevelStr)); err != nil {
		return cfg, fmt.Errorf("invalid --log-level value provided: %v", cfg.logLevelStr)
	}

	if !strings.HasPrefix(cfg.MetricsPath, "/") {
		return cfg, fmt.Errorf("invalid --metrics-path value provided: %v", cfg.MetricsPath)
	}

	switch cfg.ProgCollector.Stats.Mode {
	case statsModeDisabled, statsModeEnabled:
	case statsModeSample:
		if cfg.ProgCollector.Stats.SampleInterval <= 0 {
			return cfg, fmt.Errorf("invalid --prog-stats-sample-interval value provided: %v", cfg.ProgCollector.Stats.SampleInterval)
		}
		if cfg.ProgCollector.Stats.SampleDuration <= 0 {
			return cfg, fmt.Errorf("invalid --prog-stats-sample-duration value provided: %v", cfg.ProgCollector.Stats.SampleDuration)
		}
	default:
		return cfg, fmt.Errorf("invalid --prog-stats-mode value provided: %v", cfg.ProgCollector.Stats.Mode)
	}

	return cfg, nil
}
