FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /shinkiro cmd/shinkiro/main.go

FROM alpine:3.21
RUN apk --no-cache add ca-certificates iptables nftables tzdata
WORKDIR /root/
COPY --from=builder /shinkiro /usr/local/bin/shinkiro

EXPOSE 2222 2375 5432 6379 6443 8080

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/shinkiro"]
CMD ["up"]
