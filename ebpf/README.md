# eBPF 빌드 및 배포 가이드

이 프로젝트는 아키텍처별(amd64, arm64)로 최적화된 eBPF 오브젝트를 리눅스 환경에서 미리 생성(Pre-build)한 뒤, 이를 포함하여 멀티 아키텍처 Docker 이미지를 빌드합니다.

## 전체 빌드 워크플로우

1.  **eBPF 오브젝트 생성 (아키텍처별 리눅스 환경)**
    *   **amd64**: 일반 x86_64 리눅스 서버/VM에서 실행
    *   **arm64**: Apple Silicon Mac 위의 리눅스 VM(OrbStack, UTM 등) 또는 AWS Graviton 노드에서 실행
    *   각 환경에서 `./gen_bpf.sh`를 실행하여 `artifacts/<arch>/` 하위에 결과물을 생성합니다.
2.  **결과물 취합**: 각 환경에서 생성된 `artifacts/` 폴더의 내용을 이 프로젝트 디렉터리로 모읍니다.
3.  **이미지 빌드**: `ebpf/Makefile`을 통해 `docker buildx`로 멀티 아키텍처 이미지를 생성합니다.

---

## 1) eBPF 오브젝트 생성 (환경별)

반드시 **타겟 아키텍처와 일치하는 리눅스 커널 환경**에서 실행해야 합니다.

### [A] amd64 (Linux x86_64)
```bash
cd ebpf
# x86_64 리눅스 환경에서 실행
./gen_bpf.sh
# 생성 확인: artifacts/amd64/ 하위에 .go, .o, vmlinux.h 존재 확인
```

### [B] arm64 (Mac M1/M2/M3 리눅스 VM 등)
Apple Silicon Mac에서는 OrbStack, UTM 등을 통해 리눅스 환경을 구성한 뒤 실행합니다.
```bash
cd ebpf
# arm64 리눅스 환경에서 실행
./gen_bpf.sh
# 생성 확인: artifacts/arm64/ 하위에 .go, .o, vmlinux.h 존재 확인
```

---

## 2) Docker 이미지 빌드 (Main 환경)

모든 아키텍처의 artifacts가 준비되었다면, `docker buildx`를 지원하는 환경에서 이미지를 빌드합니다.

```bash
cd ebpf
# 멀티 아키텍처 빌드 (amd64 + arm64)
make build PUSH=true VERSION=0.1.0
```
*   `Makefile`은 `artifacts/amd64/`와 `artifacts/arm64/`에 있는 파일들을 참조하여 `Dockerfile`의 `COPY` 단계에서 적절히 주입합니다.

---

## 생성 결과물 구조
생성된 `artifacts/` 디렉터리는 다음과 같은 구조를 가져야 합니다:
```text
artifacts/
├── amd64/
│   ├── l4sender_bpfel.go, l4sender_bpfeb.go, ... (.o 파일 포함)
│   ├── l7receiver_bpfel.go, l7receiver_bpfeb.go, ... (.o 파일 포함)
│   └── vmlinux.h
└── arm64/
    ├── l4sender_bpfel.go, l4sender_bpfeb.go, ... (.o 파일 포함)
    ├── l7receiver_bpfel.go, l7receiver_bpfeb.go, ... (.o 파일 포함)
    └── vmlinux.h
```

> macOS 등 비-Linux 환경에서는 `gen_bpf.sh` 실행이 실패합니다. 실제 대상 클러스터 노드(또는 같은 커널 버전의 Linux VM/컨테이너)에서 실행하세요.
