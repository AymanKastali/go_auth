# --- Lint Stage ---
FROM golangci/golangci-lint:v2.8.0 AS linter
WORKDIR /go_auth
COPY . .
# Run linter. Build will fail if linting fails.
RUN golangci-lint run ./...

# --- Build stage ---
FROM golang:1.25 AS builder
# Copy from linter stage to ensure it ran successfully
COPY --from=linter /go_auth /go_auth
WORKDIR /go_auth
RUN go mod tidy
RUN go build -o /go_auth_bin/main ./cmd/server/main.go

# --- Final stage ---
FROM golang:1.25
WORKDIR /go_auth
COPY --from=builder /go_auth_bin/main /go_auth_bin/main
EXPOSE 8080
EXPOSE 2345
CMD ["/go_auth_bin/main"]
