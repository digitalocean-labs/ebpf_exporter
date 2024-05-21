package collectors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const (
	progSubsystem = "program"
	progIDLabel   = "prog_id"
)

// ProgCollectorConfig defines configuration options for ProgCollector.
type ProgCollectorConfig struct {
	EnableStatsCollection bool
}

// ProgCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF programs.
type ProgCollector struct {
	cfg ProgCollectorConfig

	infoDesc *prometheus.Desc

	statsRunCountDesc    *prometheus.Desc // only non-nil if enabled
	statsRunDurationDesc *prometheus.Desc // only non-nil if enabled
}

// NewProgCollector returns a prometheus.Collector for collecting metrics about currently loaded eBPF programs.
func NewProgCollector(cfg ProgCollectorConfig) *ProgCollector {
	pc := ProgCollector{
		cfg: cfg,
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, progSubsystem, "info"),
			"information on currently loaded eBPF programs",
			[]string{progIDLabel, "prog_type", "prog_name", "tag"},
			nil,
		),
	}

	if pc.cfg.EnableStatsCollection {
		pc.statsRunCountDesc = prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, progSubsystem, "run_count"),
			"Total number of times the program was called",
			[]string{progIDLabel},
			nil,
		)
		pc.statsRunDurationDesc = prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, progSubsystem, "run_duration_nanoseconds"),
			"Total accumulated runtime of the program in nanoseconds",
			[]string{"id"},
			nil,
		)
	}

	return &pc
}

// Describe implements prometheus.Collector.Describe.
func (pc *ProgCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- pc.infoDesc
}

// Collect implements prometheus.Collector.Collect.
func (pc *ProgCollector) Collect(ch chan<- prometheus.Metric) {
	progID := ebpf.ProgramID(0)
	for {
		slog.Debug("starting prog iteration", progIDLabel, progID)

		var err error
		progID, err = ebpf.ProgramGetNextID(progID)
		if errors.Is(err, os.ErrNotExist) {
			return
		} else if err != nil {
			slog.Error("error getting next program id", progIDLabel, progID, "err", err)
			prometheus.NewInvalidMetric(pc.infoDesc, fmt.Errorf("error getting next program id: %w", err))
			// this is likely a condition that isn't going to be resolved with another attempt,
			// so let's exit early.
			return
		}

		// if either of these fail, continue to trying the next program
		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			slog.Error("error program from ID", progIDLabel, progID, "err", err)
			prometheus.NewInvalidMetric(pc.infoDesc, fmt.Errorf("error getting program for ID %d: %w", progID, err))
			continue
		}
		info, err := prog.Info()
		if err != nil {
			slog.Error("error program info", progIDLabel, progID, "err", err)
			prometheus.NewInvalidMetric(pc.infoDesc, fmt.Errorf("error getting program info for ID %d: %w", progID, err))
			continue
		}

		progIDStr := strconv.FormatUint(uint64(progID), 10)
		ch <- prometheus.MustNewConstMetric(pc.infoDesc, prometheus.GaugeValue,
			1.0,
			progIDStr,
			info.Type.String(),
			info.Name,
			info.Tag,
		)

		if pc.statsRunCountDesc != nil {
			slog.Debug("collecting run count", progIDLabel, progID)
			if runCount, ok := info.RunCount(); ok {
				ch <- prometheus.MustNewConstMetric(pc.statsRunCountDesc, prometheus.CounterValue,
					float64(runCount),
					progIDStr,
				)
			} else {
				slog.Error("run count could not be retrieved", progIDLabel, progID)
				prometheus.NewInvalidMetric(pc.statsRunCountDesc, fmt.Errorf("run count could not be retrieved, stats collection may be disabled"))
			}
		}

		if pc.statsRunDurationDesc != nil {
			slog.Debug("collecting run duration", progIDLabel, progID)
			if runTime, ok := info.Runtime(); ok {
				ch <- prometheus.MustNewConstMetric(pc.statsRunDurationDesc, prometheus.CounterValue,
					float64(runTime),
					progIDStr,
				)
			} else {
				slog.Error("run duration could not be retrieved", progIDLabel, progID)
				prometheus.NewInvalidMetric(pc.statsRunCountDesc, fmt.Errorf("run time could not be retrieved, stats collection may be disabled"))
			}
		}
	}
}

// EnableProgStats enables the Linux kernel's BPF program statistics.
func EnableProgStats() (io.Closer, error) {
	statsFD, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		return nil, fmt.Errorf("failed to enable BPF program stats collection: %w", err)
	}
	return statsFD, nil
}

// EnableProgStatsSampling enables the Linux kernel's BPF program statistics on a periodic basis.
// It returns when the passed context is canceled.
func EnableProgStatsSampling(ctx context.Context, sampleInterval, sampleDuration time.Duration) {
	t := time.NewTicker(sampleInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			statsFD, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
			if err != nil {
				slog.Error("failed to enable BPF program stats collection", "err", err)
			} else {
				time.Sleep(sampleDuration)
				statsFD.Close()
			}
		}
	}
}
