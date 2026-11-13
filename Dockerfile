# Build the single Daru binary. The web UI is embedded, so the final image
# is just the binary on a minimal base. Daru itself is one binary, but it
# needs ClickHouse as a second service; see deploy/docker-compose.yml.
FROM golang:1.27.3-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/daru ./cmd/daru

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata wget && adduser -D -u 10001 daru
USER daru
COPY --from=build /out/daru /usr/local/bin/daru
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8088/api/health || exit 1
ENTRYPOINT ["daru"]
CMD ["serve"]
