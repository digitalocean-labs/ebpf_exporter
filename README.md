# ebpf_exporter

A pure-Go Prometheus exporter for the eBPF Linux subsystem. It exports metrics for currently loaded eBPF resources like programs, maps, and links.

It was partially inspired by the built-in metrics provided by [github.com/cloudflare/ebpf_exporter](https://github.com/cloudflare/ebpf_exporter). While that project was built for creating _custom_ metrics out of eBPF maps, this project aims to be a bit smaller in scope, by only exporting metrics based on information that Linux provides out-of-the-box, more akin to `node_exporter`.

It's built on top of the [Cilium eBPF Go library](github.com/cilium/ebpf).

IMPORTANT: `ebpf_exporter` must be run as a privileged process. Specifically, the `CAP_SYS_ADMIN` capability is required; `CAP_BPF` and `CAP_PERFMON` are insufficient, even on 6.x kernels.

## Design Goals

- Pure Go (never any CGO, and no `libbpf`)
- Run on any modern Linux (4.x) out of the box
- No custom eBPF metrics; only those provided by Linux by default
- Follow best practices of Prometheus exporters

## Metrics

Most metrics will have an `id` style key, on which the `info` metrics can be joined to get more information.

### Programs

- `ebpf_program_info`
- `ebpf_program_run_count`
- `ebpf_program_run_duration_nanoseconds`

#### Program stats collection

The exporter offers optional collection BPF program stats (run count and total duration), a feature offered by the Linux kernel since 5.1. In this exporter, it's only available if running on Linux 5.8 or higher.

There are 3 modes (`--prog-stats-mode`):

- `disabled`: This is the default. BPF program stats are not enabled and not collected.
- `sample`: BPF program stats are enabled only for the duration of a sampling interval, defined by the required `--prog-stats-sample-interval` and `--prog-stats-sample-duration` flags. Metrics will still be collected and exported, but they will not be incremented outside of the desired interval.
- `enabled`: BPF program stats are always enabled and collected. This is not recommended in production, especially for latency-sensitive eBPF programs, due to overhead.

NOTE: When BPF stats are enabled, they are enabled for all currently loaded BPF programs. Linux does not offer a feature to selectively enable statistics for only a subset of current programs.

### Maps

- `ebpf_map_info`
- `ebpf_map_entries`

### Links

- `ebpf_link_info`
- `ebpf_link_cgroup_info`
- `ebpf_link_netns_info`
- `ebpf_link_tracing_info`
- `ebpf_link_xdp_info`
- `ebpf_link_tcx_info`
- `ebpf_link_netfilter_info`
- `ebpf_link_netkit_info`
- `ebpf_link_kprobe_info`
- `ebpf_link_perf_event_info`

### BTF

- `ebpf_btf_info`
