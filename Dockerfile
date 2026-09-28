# Ultra-optimized Multi-stage Go build for VPS with 500+ users/min
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
# VPS-optimized build flags for maximum performance
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -tags netgo \
    -installsuffix netgo \
    -o /app/yume-proxy main.go

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/yume-proxy /app/yume-proxy
EXPOSE 5001
ENV PORT=5001
ENV GOMAXPROCS=4
ENV GOGC=100
CMD ["/app/yume-proxy"]
