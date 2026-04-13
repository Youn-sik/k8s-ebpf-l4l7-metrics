PROJECT ?= library/k8s-ebpf-l4l7-metrics
VERSION ?= 0.0.01
REGISTRY ?= registry.skuberplus.com
IMAGE ?= $(REGISTRY)/$(PROJECT):$(VERSION)
GO_VERSION ?= 1.25.9
# buildx multi-arch settings
PLATFORMS ?= linux/amd64,linux/arm64
PUSH ?= false
NAMESPACE ?= skuber-system

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make build      # docker image build (amd64 + arm64)"
	@echo "  make push       # docker push"
	@echo "  make deploy     # kubectl apply daemonset (envsubst)"
	@echo ""
	@echo "필수 사항:"
	@echo "  - 빌드 전 artifacts/amd64/ 및 artifacts/arm64/ 폴더에"
	@echo "    bpf2go 산출물(.go, .o, vmlinux.h)이 모두 있는지 확인하십시오."
	@echo "  - 산출물은 각 아키텍처별 리눅스 환경에서 gen_bpf.sh로 생성해야 합니다."
	@echo ""
	@echo "Vars: PROJECT, VERSION, REGISTRY, IMAGE, GO_VERSION, PLATFORMS, PUSH, NAMESPACE"

.PHONY: build
build:
	OUT_OPT=$$( if [ "$(PUSH)" = "true" ]; then echo "--push"; else echo "--load"; fi ); \
	docker buildx build --no-cache --platform=$(PLATFORMS) \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(IMAGE) $$OUT_OPT -f Dockerfile .

.PHONY: push
push:
	docker push $(IMAGE)

.PHONY: deploy
deploy:
	IMAGE=$(IMAGE) NAMESPACE=$(NAMESPACE) ./kubernetes/deploy.sh

.PHONY: clean
clean:
	rm -f bin/agent
