FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/shinkiro cmd/shinkiro/main.go

FROM alpine:3.21
RUN apk --no-cache add ca-certificates iptables nftables tzdata \
	&& mkdir -p /app/data /etc/shinkiro

# Binary path shared by Compose ENTRYPOINT and Helm command
COPY --from=builder /out/shinkiro /usr/local/bin/shinkiro

# App loads config.yaml + playbooks.yaml relative to CWD (see cmd/shinkiro/main.go).
# Keep copies under /etc/shinkiro for operators who prefer absolute paths.
WORKDIR /app
COPY config.yaml playbooks.yaml /app/
COPY config.yaml playbooks.yaml /etc/shinkiro/

# audit_log_path defaults to data/events.jsonl (relative to WORKDIR)
VOLUME ["/app/data"]

EXPOSE 502 1053 1883 2222 2323 2375 2525 4445 5432 6379 6443 8080 8169 9100 9200 27017

ENTRYPOINT ["/usr/local/bin/shinkiro"]
CMD ["up"]
