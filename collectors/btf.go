package collectors

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf/btf"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	btfSubsystem = "btf"
	btfIDLabel   = "btf_id"
)

// BTFCollectorConfig defines configuration options for BTFCollector.
type BTFCollectorConfig struct {
}

// BTFCollector implements prometheus.Collector for collecting metrics about currently loaded BTF (BPF Type Format) objects.
type BTFCollector struct {
	cfg BTFCollectorConfig

	infoDesc *prometheus.Desc
}

// NewBTFCollector returns a prometheus.Collector for collecting metrics about currently active eBPF links.
func NewBTFCollector(cfg BTFCollectorConfig) *BTFCollector {
	return &BTFCollector{
		cfg: cfg,
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, btfSubsystem, "info"),
			"information on currently loaded BTF objects",
			[]string{btfIDLabel, "btf_name", "is_kernel"},
			nil,
		),
	}
}

// Describe implements prometheus.Collector.Describe.
func (lc *BTFCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lc.infoDesc
}

// Collect implements prometheus.Collector.Collect.
func (lc *BTFCollector) Collect(ch chan<- prometheus.Metric) {
	iter := btf.HandleIterator{}
	defer iter.Handle.Close()

	for iter.Next() {
		slog.Debug("starting BTF iteration", btfIDLabel, iter.ID)

		info, err := iter.Handle.Info()
		if err != nil {
			slog.Error("error BTF info", btfIDLabel, info.ID, "err", err)
			prometheus.NewInvalidMetric(lc.infoDesc, fmt.Errorf("error getting BTF info for ID %d: %w", info.ID, err))
			continue
		}

		btfIDStr := strconv.FormatUint(uint64(info.ID), 10)
		ch <- prometheus.MustNewConstMetric(
			lc.infoDesc,
			prometheus.GaugeValue,
			1.0,
			btfIDStr,
			info.Name,
			strconv.FormatBool(info.IsKernel),
		)
	}

	err := iter.Err()
	if err != nil {
		slog.Error("error iterating over BTF objects", "err", err)
		prometheus.NewInvalidMetric(lc.infoDesc, fmt.Errorf("error iterating over BTF objects: %w", err))
	}
}
