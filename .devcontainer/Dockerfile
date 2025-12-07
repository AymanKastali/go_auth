# Build stage
FROM golang:1.25 AS builder

WORKDIR /go_auth

# Copy modules and download deps
COPY go.mod go.sum ./
RUN go mod tidy

# Copy source
COPY . .

# Build the Go Fiber binary
RUN go build -o /go_auth_bin/main ./src/cmd/api/main.go

# Final stage
FROM golang:1.25

WORKDIR /go_auth

# Copy the binary from builder
COPY --from=builder /go_auth_bin/main /go_auth_bin/main

# Expose port for Fiber
EXPOSE 8080

# Run the server
CMD ["/go_auth_bin/main"]
