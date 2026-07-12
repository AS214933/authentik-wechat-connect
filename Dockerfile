FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN go test ./... && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/wechat-connect ./cmd/server

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser && mkdir -p /app/data && chown -R appuser:appuser /app
WORKDIR /app
USER appuser
COPY --from=build --chown=appuser:appuser /out/wechat-connect /app/wechat-connect
EXPOSE 8080
ENTRYPOINT ["/app/wechat-connect"]
