# Stage 1 — Build
FROM golang:1.25-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./docs ./docs
COPY ./config ./config
ARG VERSION=dev
RUN go build -ldflags="-s -w -X main.version=${VERSION}" -o /main ./cmd/auth/

# Stage 2 — Runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /
COPY --from=builder /main /main
COPY --from=builder /app/config /config
EXPOSE 8080
USER appuser
ENTRYPOINT ["/main"]
