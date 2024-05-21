.PHONY: all build build-bin lint test docker-build docker-run

all: lint build test

build:
	GOOS=linux go build ./...

build-bin:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "./bin/ebpf_exporter_linux_amd64" ./cmd/ebpf_exporter
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "./bin/ebpf_exporter_linux_arm64" ./cmd/ebpf_exporter

lint:
	revive ./...
	GOOS=linux staticcheck ./...

test:
	go test -v ./...

DOCKER_IMAGE ?= "digitalocean/ebpf_exporter"

docker-build:
	docker build --platform=linux/amd64 --platform=linux/arm64 -t $(DOCKER_IMAGE) .

docker-run: docker-build
	docker run --rm --privileged -p 11000:11000 $(DOCKER_IMAGE)
