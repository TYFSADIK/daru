# Build the single Daru binary. The web UI is embedded, so the final image
# is just the binary on a minimal base.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/daru ./cmd/daru

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 daru
USER daru
COPY --from=build /out/daru /usr/local/bin/daru
EXPOSE 8088
ENTRYPOINT ["daru"]
CMD ["serve"]
