# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY . .
RUN go build -o /dirfuzz-monitor ./cmd/monitor

FROM alpine:3.20
WORKDIR /app

COPY --from=builder /dirfuzz-monitor /dirfuzz-monitor

# Mark /data as stateful storage for persisted monitor baselines.
VOLUME ["/data"]

ENTRYPOINT ["/dirfuzz-monitor"]
