FROM golang:1.25

WORKDIR /workspaces

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

CMD ["sleep", "infinity"]