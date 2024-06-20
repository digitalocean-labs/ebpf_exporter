FROM golang:1.22.4 AS builder

WORKDIR /ebpf_exporter

COPY go.mod go.sum ./
RUN go mod download

COPY ./cmd ./cmd
COPY ./collectors ./collectors
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "/bin/ebpf_exporter" ./cmd/ebpf_exporter

FROM scratch

COPY --from=builder /bin/ebpf_exporter /ebpf_exporter
ENTRYPOINT [ "/ebpf_exporter" ]
