# Multi-stage Go build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/yume-proxy main.go

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/yume-proxy /app/yume-proxy
EXPOSE 5001
ENV PORT=5001
CMD ["/app/yume-proxy"]
