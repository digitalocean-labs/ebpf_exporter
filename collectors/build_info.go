package collectors

import (
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
)

// NewBuildInfoCollector returns a prometheus.Collector that exports a gauge with build information about ebpf_exporter.
func NewBuildInfoCollector() prometheus.Collector {
	var versionCommit string
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				versionCommit = s.Value
				break
			}
		}
	}

	return prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: ebpfExporterNamespace,
			Name:      "build_info",
			Help:      "A metric with a constant '1' value labeled by the revision (Git commit) from which ebpf_exporter was built.",
			ConstLabels: prometheus.Labels{
				"revision": versionCommit,
			},
		},
		func() float64 { return 1 },
	)
}
