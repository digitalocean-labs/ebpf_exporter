package collectors

import (
	"encoding"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	mapSubsystem = "map"
	mapIDLabel   = "map_id"
)

// MapCollectorConfig defines configuration options for MapCollector.
type MapCollectorConfig struct {
	CountEntries bool
}

// MapCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF maps.
type MapCollector struct {
	cfg MapCollectorConfig

	infoDesc        *prometheus.Desc
	maxEntriesDesc  *prometheus.Desc
	currEntriesDesc *prometheus.Desc
}

// NewMapCollector returns a prometheus.Collector for collecting metrics about currently loaded eBPF maps.
func NewMapCollector(cfg MapCollectorConfig) *MapCollector {
	m := MapCollector{
		cfg: cfg,
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, mapSubsystem, "info"),
			"information on currently loaded eBPF maps",
			[]string{mapIDLabel, "map_type", "map_name", "key_size", "value_size", "flags"},
			nil,
		),
		maxEntriesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, mapSubsystem, "max_entries"),
			"the configured max entries attribute of an eBPF map",
			[]string{mapIDLabel},
			nil,
		),
	}

	if m.cfg.CountEntries {
		m.currEntriesDesc = prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, mapSubsystem, "entries"),
			"The current number of entries in an eBPF map",
			[]string{mapIDLabel},
			nil,
		)
	}

	return &m
}

// Describe implements prometheus.Collector.Describe.
func (mc *MapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mc.infoDesc
}

// Collect implements prometheus.Collector.Collect.
func (mc *MapCollector) Collect(ch chan<- prometheus.Metric) {
	mapID := ebpf.MapID(0)
	for {
		slog.Debug("starting map iteration", mapIDLabel, mapID)

		var err error
		mapID, err = ebpf.MapGetNextID(mapID)
		if errors.Is(err, os.ErrNotExist) {
			return
		} else if err != nil {
			slog.Error("error getting next map id", mapIDLabel, mapID, "err", err)
			prometheus.NewInvalidMetric(mc.infoDesc, fmt.Errorf("error getting next map id: %w", err))
			// this is likely a condition that isn't going to be resolved with another attempt,
			// so let's exit early.
			return
		}

		// logging and error handling are handled in collectForMap.
		mc.collectForMap(mapID, ch)
	}
}

func (mc *MapCollector) collectForMap(mapID ebpf.MapID, ch chan<- prometheus.Metric) {
	m, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		slog.Error("error getting map from ID", mapIDLabel, mapID, "err", err)
		ch <- prometheus.NewInvalidMetric(mc.infoDesc, fmt.Errorf("error getting map for ID %d: %w", mapID, err))
		return
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		slog.Error("error getting map info", mapIDLabel, mapID, "err", err)
		ch <- prometheus.NewInvalidMetric(mc.infoDesc, fmt.Errorf("error getting map info for ID %d: %w", mapID, err))
		return
	}

	ch <- prometheus.MustNewConstMetric(mc.infoDesc, prometheus.GaugeValue,
		1.0,
		strconv.FormatUint(uint64(mapID), 10),
		info.Type.String(),
		info.Name,
		strconv.FormatUint(uint64(info.KeySize), 10),
		strconv.FormatUint(uint64(info.ValueSize), 10),
		strconv.FormatUint(uint64(m.Flags()), 10),
	)

	ch <- prometheus.MustNewConstMetric(mc.maxEntriesDesc, prometheus.GaugeValue,
		float64(info.MaxEntries),
		strconv.FormatUint(uint64(mapID), 10),
	)

	if mc.currEntriesDesc != nil && mapTypeIsIterable(m.Type()) {
		var count uint64
		throwawayKey := discardEncoding{}
		throwawayValues := make(sliceDiscardEncoding, 0)
		iter := m.Iterate()
		for iter.Next(&throwawayKey, &throwawayValues) {
			count++
		}
		if err := iter.Err(); err != nil {
			slog.Error("error iterating over map", mapIDLabel, mapID, "err", err)
			ch <- prometheus.NewInvalidMetric(mc.currEntriesDesc, fmt.Errorf("failed to iterate over map with ID %d: %v", mapID, err))
		} else {
			ch <- prometheus.MustNewConstMetric(mc.currEntriesDesc, prometheus.GaugeValue,
				float64(count),
				strconv.FormatUint(uint64(mapID), 10),
			)
		}
	}
}

func mapTypeIsIterable(typ ebpf.MapType) bool {
	return typ != ebpf.PerfEventArray
}

// Assert that discardEncoding implements the correct interfaces for map iterators.
var (
	_ encoding.BinaryUnmarshaler = (*discardEncoding)(nil)
	_ encoding.BinaryUnmarshaler = (*sliceDiscardEncoding)(nil)
)

// discardEncoding implements encoding.BinaryMarshaler for eBPF map values such that everything is discarded.
type discardEncoding struct {
}

func (de *discardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}

// sliceDiscardEncoding implements encoding.BinaryMarshaler for eBPF per-cpu map values such that everything is discarded.
type sliceDiscardEncoding []discardEncoding

func (sde *sliceDiscardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}
