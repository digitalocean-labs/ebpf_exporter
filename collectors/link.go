package collectors

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	linkSubsystem   = "link"
	linkIDLabel     = "link_id"
	attachTypeLabel = "attach_type"
	ifIndexLabel    = "interface_index"
)

// LinkCollectorConfig defines configuration options for LinkCollector.
type LinkCollectorConfig struct {
}

// LinkCollector implements prometheus.Collector for collecting metrics about currently active eBPF links.
type LinkCollector struct {
	cfg LinkCollectorConfig

	infoDesc *prometheus.Desc

	// additional optional info based on link type
	cgroupInfoDesc      *prometheus.Desc
	netnsInfoDesc       *prometheus.Desc
	tracingInfoDesc     *prometheus.Desc
	xdpInfoDesc         *prometheus.Desc
	tcxInfoDesc         *prometheus.Desc
	netfilterInfoDesc   *prometheus.Desc
	netkitInfoDesc      *prometheus.Desc
	kprobeMultiInfoDesc *prometheus.Desc
	perfEventInfoDesc   *prometheus.Desc
}

// NewLinkCollector returns a prometheus.Collector for collecting metrics about currently active eBPF links.
func NewLinkCollector(cfg LinkCollectorConfig) *LinkCollector {
	return &LinkCollector{
		cfg: cfg,
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "info"),
			"information on currently loaded eBPF links",
			[]string{linkIDLabel, "link_type", progIDLabel},
			nil,
		),

		cgroupInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "cgroup_info"),
			"additional information on currently loaded eBPF links of type Cgroup",
			[]string{linkIDLabel, attachTypeLabel, "cgroup_id"},
			nil,
		),
		netnsInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "netns_info"),
			"additional information on currently loaded eBPF links of type netns",
			[]string{linkIDLabel, attachTypeLabel, "netns_ino"},
			nil,
		),
		tracingInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "tracing_info"),
			"additional information on currently loaded eBPF links of type tracing",
			[]string{linkIDLabel, attachTypeLabel, "target_obj_id", "target_btf_id"},
			nil,
		),
		xdpInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "xdp_info"),
			"additional information on currently loaded eBPF links of type XDP",
			[]string{linkIDLabel, ifIndexLabel},
			nil,
		),
		tcxInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "tcx_info"),
			"additional information on currently loaded eBPF links of type TCX",
			[]string{linkIDLabel, attachTypeLabel, ifIndexLabel},
			nil,
		),
		netfilterInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "netfilter_info"),
			"additional information on currently loaded eBPF links of type NetFilter",
			[]string{linkIDLabel, "pf", "hook_num", "priority", "flags"},
			nil,
		),
		netkitInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "netkit_info"),
			"additional information on currently loaded eBPF links of type NetKit",
			[]string{linkIDLabel, attachTypeLabel, ifIndexLabel},
			nil,
		),
		kprobeMultiInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "kprobe_info"),
			"additional information on currently loaded eBPF links of type kprobe",
			[]string{linkIDLabel, "count", "flags", "missed"},
			nil,
		),
		perfEventInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(ebpfNamespace, linkSubsystem, "perf_event_info"),
			"additional information on currently loaded eBPF links of type perf event",
			[]string{linkIDLabel, "perf_event_type"},
			nil,
		),
	}
}

// Describe implements prometheus.Collector.Describe.
func (lc *LinkCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lc.infoDesc

	ch <- lc.cgroupInfoDesc
	ch <- lc.netnsInfoDesc
	ch <- lc.tracingInfoDesc
	ch <- lc.xdpInfoDesc
	ch <- lc.netfilterInfoDesc
	ch <- lc.netkitInfoDesc
	ch <- lc.kprobeMultiInfoDesc
	ch <- lc.perfEventInfoDesc
}

// Collect implements prometheus.Collector.Collect.
func (lc *LinkCollector) Collect(ch chan<- prometheus.Metric) {
	iter := link.Iterator{}
	defer iter.Close()

	for iter.Next() {
		slog.Debug("starting link iteration", linkIDLabel, iter.ID)

		info, err := iter.Link.Info()
		if err != nil {
			slog.Error("error link info", linkIDLabel, info.ID, "err", err)
			prometheus.NewInvalidMetric(lc.infoDesc, fmt.Errorf("error getting link info for ID %d: %w", info.ID, err))
			continue
		}

		linkIDStr := strconv.FormatUint(uint64(info.ID), 10)
		ch <- prometheus.MustNewConstMetric(
			lc.infoDesc,
			prometheus.GaugeValue,
			1.0,
			linkIDStr,
			linkTypeToString(info.Type),
			strconv.FormatUint(uint64(info.Program), 10),
		)

		var extraDesc *prometheus.Desc
		var extraLabelValues []string
		switch info.Type {
		case link.CgroupType:
			if extra := info.Cgroup(); extra != nil {
				extraDesc = lc.cgroupInfoDesc
				extraLabelValues = append(extraLabelValues,
					attachTypeToString(uint32(extra.AttachType)),
					strconv.FormatUint(uint64(extra.CgroupId), 10),
				)
			}
		case link.NetNsType:
			if extra := info.NetNs(); extra != nil {
				extraDesc = lc.netnsInfoDesc
				extraLabelValues = append(extraLabelValues,
					attachTypeToString(uint32(extra.AttachType)),
					strconv.FormatUint(uint64(extra.NetnsIno), 10),
				)
			}
		case link.TracingType:
			if extra := info.Tracing(); extra != nil {
				extraDesc = lc.tracingInfoDesc
				extraLabelValues = append(extraLabelValues,
					attachTypeToString(uint32(extra.AttachType)),
					strconv.FormatUint(uint64(extra.TargetObjId), 10),
					strconv.FormatUint(uint64(extra.TargetBtfId), 10),
				)
			}
		case link.XDPType:
			if extra := info.XDP(); extra != nil {
				extraDesc = lc.xdpInfoDesc
				extraLabelValues = append(extraLabelValues,
					strconv.FormatUint(uint64(extra.Ifindex), 10),
				)
			}
		case link.TCXType:
			if extra := info.TCX(); extra != nil {
				extraDesc = lc.tcxInfoDesc
				extraLabelValues = append(extraLabelValues,
					attachTypeToString(uint32(extra.AttachType)),
					strconv.FormatUint(uint64(extra.Ifindex), 10),
				)
			}
		case link.NetfilterType:
			if extra := info.Netfilter(); extra != nil {
				extraDesc = lc.netfilterInfoDesc
				extraLabelValues = append(extraLabelValues,
					strconv.FormatUint(uint64(extra.Pf), 10),
					strconv.FormatUint(uint64(extra.Hooknum), 10),
					strconv.FormatInt(int64(extra.Priority), 10),
					strconv.FormatUint(uint64(extra.Flags), 10),
				)
			}
		case link.NetkitType:
			if extra := info.Netkit(); extra != nil {
				extraDesc = lc.netkitInfoDesc
				extraLabelValues = append(extraLabelValues,
					attachTypeToString(uint32(extra.AttachType)),
					strconv.FormatUint(uint64(extra.Ifindex), 10),
				)
			}
		case link.KprobeMultiType:
			if extra := info.KprobeMulti(); extra != nil {
				extraDesc = lc.kprobeMultiInfoDesc

				if count, ok := extra.AddressCount(); ok {
					strconv.FormatUint(uint64(count), 10)
				}
				if flags, ok := extra.Flags(); ok {
					strconv.FormatUint(uint64(flags), 10)
				}
				if missed, ok := extra.Missed(); ok {
					strconv.FormatUint(missed, 10)
				}
			}
		case link.PerfEventType:
			if extra := info.PerfEvent(); extra != nil {
				extraDesc = lc.perfEventInfoDesc

				extraLabelValues = append(extraLabelValues,
					perfTypeToString(uint32(extra.Type)),
				)
			}
		}

		if extraDesc != nil {
			ch <- prometheus.MustNewConstMetric(
				extraDesc,
				prometheus.GaugeValue,
				1.0,
				append([]string{linkIDStr}, extraLabelValues...)...,
			)
		}
	}

	err := iter.Err()
	if err != nil {
		slog.Error("error iterating over links", "err", err)
		prometheus.NewInvalidMetric(lc.infoDesc, fmt.Errorf("error iterating over links: %w", err))
	}
}

func linkTypeToString(linkType link.Type) string {
	lts := map[link.Type]string{
		link.UnspecifiedType:   "UNSPEC",
		link.RawTracepointType: "RAW_TRACEPOINT",
		link.TracingType:       "TRACING",
		link.CgroupType:        "CGROUP",
		link.IterType:          "ITER",
		link.NetNsType:         "NETNS",
		link.XDPType:           "XDP",
		link.PerfEventType:     "PERF_EVENT",
		link.KprobeMultiType:   "KPROBE_MULTI",
		link.TCXType:           "TCX",
		link.UprobeMultiType:   "UPROBE_MULTI",
		link.NetfilterType:     "NETFILTER",
		link.NetkitType:        "NETKIT",
	}

	if s, ok := lts[linkType]; ok {
		return s
	}
	return strconv.FormatUint(uint64(linkType), 10)
}

func perfTypeToString(perfType uint32) string {
	pts := map[uint32]string{
		0: "UNSPEC",
		1: "UPROBE",
		2: "URETPROBE",
		3: "KPROBE",
		4: "KRETPROBE",
		5: "TRACEPOINT",
		6: "EVENT",
	}

	if s, ok := pts[perfType]; ok {
		return s
	}
	return strconv.FormatUint(uint64(perfType), 10)
}

func attachTypeToString(attachType uint32) string {
	ats := map[uint32]string{
		0:  "CGROUP_INET_INGRESS",
		1:  "CGROUP_INET_EGRESS",
		2:  "CGROUP_INET_SOCK_CREATE",
		3:  "CGROUP_SOCK_OPS",
		4:  "SK_SKB_STREAM_PARSER",
		5:  "SK_SKB_STREAM_VERDICT",
		6:  "CGROUP_DEVICE",
		7:  "SK_MSG_VERDICT",
		8:  "CGROUP_INET4_BIND",
		9:  "CGROUP_INET6_BIND",
		10: "CGROUP_INET4_CONNECT",
		11: "CGROUP_INET6_CONNECT",
		12: "CGROUP_INET4_POST_BIND",
		13: "CGROUP_INET6_POST_BIND",
		14: "CGROUP_UDP4_SENDMSG",
		15: "CGROUP_UDP6_SENDMSG",
		16: "LIRC_MODE2",
		17: "FLOW_DISSECTOR",
		18: "CGROUP_SYSCTL",
		19: "CGROUP_UDP4_RECVMSG",
		20: "CGROUP_UDP6_RECVMSG",
		21: "CGROUP_GETSOCKOPT",
		22: "CGROUP_SETSOCKOPT",
		23: "TRACE_RAW_TP",
		24: "TRACE_FENTRY",
		25: "TRACE_FEXIT",
		26: "MODIFY_RETURN",
		27: "LSM_MAC",
		28: "TRACE_ITER",
		29: "CGROUP_INET4_GETPEERNAME",
		30: "CGROUP_INET6_GETPEERNAME",
		31: "CGROUP_INET4_GETSOCKNAME",
		32: "CGROUP_INET6_GETSOCKNAME",
		33: "XDP_DEVMAP",
		34: "CGROUP_INET_SOCK_RELEASE",
		35: "XDP_CPUMAP",
		36: "SK_LOOKUP",
		37: "XDP",
		38: "SK_SKB_VERDICT",
		39: "SK_REUSEPORT_SELECT",
		40: "SK_REUSEPORT_SELECT_OR_MIGRATE",
		41: "PERF_EVENT",
		42: "TRACE_KPROBE_MULTI",
		43: "LSM_CGROUP",
		44: "STRUCT_OPS",
		45: "NETFILTER",
		46: "TCX_INGRESS",
		47: "TCX_EGRESS",
		48: "TRACE_UPROBE_MULTI",
		49: "CGROUP_UNIX_CONNECT",
		50: "CGROUP_UNIX_SENDMSG",
		51: "CGROUP_UNIX_RECVMSG",
		52: "CGROUP_UNIX_GETPEERNAME",
		53: "CGROUP_UNIX_GETSOCKNAME",
		54: "NETKIT_PRIMARY",
		55: "NETKIT_PEER",
	}

	if s, ok := ats[attachType]; ok {
		return s
	}
	return strconv.FormatUint(uint64(attachType), 10)
}
