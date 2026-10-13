# SPDX-FileCopyrightText: Copyright (c) 2026 the cautem authors
# SPDX-License-Identifier: Apache-2.0
#
# Build from a workspace that has sibling checkouts (CI does this):
#   docker build -f cautem-gateway/Dockerfile -t cautem-gateway:local .

FROM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY cautem-core ./cautem-core
COPY cautem-display ./cautem-display
COPY cautem-providers ./cautem-providers
COPY cautem-runtime ./cautem-runtime
COPY cautem-cli ./cautem-cli
COPY cautem-proxy ./cautem-proxy
COPY cautem-driver ./cautem-driver
COPY cautem-sdk ./cautem-sdk
COPY cautem-slogx ./cautem-slogx
COPY cautem-proto ./cautem-proto
COPY cautem-gateway ./cautem-gateway
WORKDIR /src/cautem-gateway
ARG TARGETARCH
RUN set -eu; arch="${TARGETARCH:-$(go env GOARCH)}"; mkdir -p /out/helpers/linux-$arch; \
	CGO_ENABLED=0 go build -o /out/cautem-gateway ./cmd/cautem-gateway; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cautem-cli -o /out/helpers/linux-$arch/cautem ./cmd/cautem; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cautem-runtime -o /out/helpers/linux-$arch/cautem-init ./cmd/cautem-init; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cautem-runtime -o /out/helpers/linux-$arch/cautem-sshd ./cmd/cautem-sshd; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/cautem-runtime -o /out/helpers/linux-$arch/cautem-supervisor ./cmd/cautem-supervisor

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cautem-gateway /usr/local/bin/cautem-gateway
COPY --from=build /out/helpers/ /usr/local/lib/cautem/
COPY --from=build /src/cautem-cli/providers/ /usr/local/providers/
COPY --from=build /src/cautem-gateway/LICENSE /src/cautem-gateway/NOTICE /usr/share/licenses/cautem-gateway/
COPY --from=build /src/cautem-cli/LICENSE /src/cautem-cli/NOTICE /usr/share/licenses/cautem-cli/
COPY --from=build /src/cautem-runtime/LICENSE /src/cautem-runtime/NOTICE /usr/share/licenses/cautem-runtime/
LABEL org.opencontainers.image.title="cautem-gateway" \
      org.opencontainers.image.description="cautem control-plane gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cautem/cautem-gateway"
ENV CAUTEM_GATEWAY_DATA=/var/lib/cautem-gateway
VOLUME ["/var/lib/cautem-gateway"]
EXPOSE 7443
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7443/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/cautem-gateway"]
CMD ["--listen", "0.0.0.0:7443", "--data-dir", "/var/lib/cautem-gateway"]
