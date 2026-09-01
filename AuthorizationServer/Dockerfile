# Build stage
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Build static binary with trimpath and stripped debug symbols
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-w -s" \
    -o /app/authserver \
    ./AuthorizationServer/cmd/server

# Final runtime stage
FROM --platform=$TARGETPLATFORM alpine:3.20

# Install CA certificates and create non-root user for Kubernetes security
RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/authserver /app/authserver

# Switch to non-root user
USER appuser:appgroup

EXPOSE 8080

ENTRYPOINT ["/app/authserver"]
