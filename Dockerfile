FROM golang:1.27.0 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o govpn examples/sample_client/main.go


FROM scratch
WORKDIR /app
COPY --from=builder /app/govpn ./
ENTRYPOINT ["/app/govpn", "-server"]
CMD ["-config", "/app/config.json"]
