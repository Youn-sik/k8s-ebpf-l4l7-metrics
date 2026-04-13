# Build agent binary
ARG GO_VERSION=1.25.9
FROM golang:${GO_VERSION}-alpine AS builder

# buildx가 주입하는 타깃 아키텍처/OS 사용
ARG TARGETARCH
ARG TARGETOS
# 필요 시 수동으로 덮어쓸 수 있도록 ARTIFACT_ARCH 추가(기본은 TARGETARCH)
ARG ARTIFACT_ARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} GO111MODULE=on

WORKDIR /src

# 나머지 소스 먼저 복사
COPY . .

# 아키텍처별로 미리 생성한 bpf2go 산출물을 cmd/agent/에 복사 (package main)
# bpf2go는 _bpfel (little-endian), _bpfeb (big-endian) 파일 생성
# Go 빌드 태그가 자동으로 올바른 파일 선택
# CO-RE: 실행 시점에 BTF를 통해 커널 버전에 맞게 재배치
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l4sender_bpfel.go ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l4sender_bpfeb.go ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l4sender_bpfel.o ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l4sender_bpfeb.o ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l7receiver_bpfel.go ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l7receiver_bpfeb.go ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l7receiver_bpfel.o ./cmd/agent/
COPY artifacts/${ARTIFACT_ARCH:-${TARGETARCH}}/l7receiver_bpfeb.o ./cmd/agent/

RUN go mod download
RUN go build -o /out/agent ./cmd/agent

# Minimal runtime image
FROM scratch
WORKDIR /
COPY --from=builder /out/agent /agent
ENTRYPOINT ["/agent"]
