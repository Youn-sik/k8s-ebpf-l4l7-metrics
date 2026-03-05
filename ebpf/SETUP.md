# eBPF 빌드 사전 준비 및 환경 구성

eBPF C 코드를 빌드하고 Go 바인딩을 생성하기 위해서는 **해당 아키텍처의 리눅스 커널 환경**이 반드시 필요합니다.

## 1) 아키텍처별 환경 준비

### Mac (Apple Silicon: M1, M2, M3 등) 사용자
Apple Silicon Mac은 `arm64` 기반이므로, 아래 도구 중 하나를 사용해 리눅스 VM을 실행하십시오.
- **OrbStack (강력 추천)**: 가장 가볍고 빠릅니다. `orb create ubuntu`로 즉시 머신 생성 가능.
- **UTM**: 무료이며 GUI 기반으로 Ubuntu 등 리눅스 설치 가능.
- **Colima**: `colima start --arch arm64`로 가벼운 리눅스 환경 구성 가능.

### amd64 (x86_64) 환경
- 일반적인 x86_64 리눅스 서버나 클라우드 VM(EC2 등)을 사용하십시오.

---

## 2) 필수 패키지 설치 (Linux 환경 공통)

리눅스 VM 접속 후 아래 명령을 통해 빌드 도구를 설치합니다.

```bash
sudo apt-get update
sudo apt-get install -y wget tar clang llvm libbpf-dev bpftool linux-headers-$(uname -r)
```

## 3) Go 및 bpf2go 설치
```bash
# Go 설치 (예: 1.25.0)
wget https://go.dev/dl/go1.25.0.linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/').tar.gz
sudo tar -C /usr/local -xzf go1.25.0.linux-*.tar.gz
export PATH=$PATH:/usr/local/go/bin

# bpf2go 설치
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## 4) 빌드 실행 및 추출

각 환경(amd64, arm64)에서 이 저장소를 클론하거나 `ebpf/` 디렉터리를 복사한 뒤 실행합니다.

```bash
cd ebpf
# 아키텍처는 uname -m에 의해 자동으로 감지됩니다.
./gen_bpf.sh
```

**중요**: 빌드가 완료되면 `ebpf/artifacts/<arch>/` 디렉터리에 생성된 파일들을 메인 작업 환경(Docker 빌드를 수행할 환경)의 동일한 위치로 복사하십시오.
