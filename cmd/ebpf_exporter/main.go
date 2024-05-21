// Package main is a Prometheus exporter for metrics about the Linux eBPF subsystem.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/digitalocean-labs/ebpf_exporter/collectors"

	"github.com/mdlayher/sdnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

func main() {
	if err := realMain(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func realMain() error {
	rootCtx, stop := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer stop()

	cfg, err := initConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	slog.SetLogLoggerLevel(cfg.LogLevel)

	enabledCollectors := []prometheus.Collector{
		collectors.NewBuildInfoCollector(),
	}

	if cfg.ProgCollector.Enabled {
		switch cfg.ProgCollector.Stats.Mode {
		case statsModeDisabled:
		case statsModeSample:
			go collectors.EnableProgStatsSampling(rootCtx, cfg.ProgCollector.Stats.SampleInterval, cfg.ProgCollector.Stats.SampleDuration)
		case statsModeEnabled:
			closer, err := collectors.EnableProgStats()
			if err != nil {
				return err
			}
			defer closer.Close()
		}

		progCfg := collectors.ProgCollectorConfig{
			EnableStatsCollection: cfg.ProgCollector.Stats.Mode != statsModeDisabled,
		}
		enabledCollectors = append(enabledCollectors, collectors.NewProgCollector(progCfg))
	}
	if cfg.MapCollector.Enabled {
		enabledCollectors = append(enabledCollectors, collectors.NewMapCollector(cfg.MapCollector.Config))
	}
	if cfg.LinkCollector.Enabled {
		enabledCollectors = append(enabledCollectors, collectors.NewLinkCollector(cfg.LinkCollector.Config))
	}
	if cfg.BTFCollector.Enabled {
		enabledCollectors = append(enabledCollectors, collectors.NewBTFCollector(cfg.BTFCollector.Config))
	}

	prometheus.MustRegister(enabledCollectors...)

	mux := http.NewServeMux()
	mux.Handle(
		fmt.Sprintf("%s %s", http.MethodGet, cfg.MetricsPath),
		promhttp.Handler(),
	)
	srv := &http.Server{
		Handler: mux,
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer srv.Shutdown(shutdownCtx)

	for _, addr := range cfg.ListenAddrs {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to create listener with address %q: %w", addr, err)
		}
		slog.Info("serving", "addr", addr, "path", cfg.MetricsPath)
		go func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("failed to serve HTTP", "err", err)
			}
		}()
	}

	if cfg.SdNotify {
		sdn, err := sdnotify.New()
		if err != nil {
			return fmt.Errorf("failed to create sdnotify handle: %w", err)
		}
		defer sdn.Close()

		sdn.Notify(sdnotify.Ready)
		defer sdn.Notify(sdnotify.Stopping)
	}

	// wait for a signal
	<-rootCtx.Done()
	slog.Info("shutting down")
	return nil
}
