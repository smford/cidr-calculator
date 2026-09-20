# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

RUN apk --no-cache add ca-certificates git

# Cache dependency layer
COPY go.mod ./
RUN go mod download

# Copy source files
COPY . .

# Build statically linked binary with stripped debug symbols
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X 'github.com/smford/cidr-calculator/internal/cli.Version=${VERSION}' -X 'github.com/smford/cidr-calculator/internal/cli.Commit=${COMMIT}' -X 'github.com/smford/cidr-calculator/internal/cli.BuildDate=${DATE}'" \
    -o /cidr-calculator \
    .

# Minimal scratch runtime stage
FROM scratch

# Import root SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import binary
COPY --from=builder /cidr-calculator /usr/local/bin/cidr-calculator

# Run as non-root user (nobody)
USER 65534:65534

ENTRYPOINT ["/usr/local/bin/cidr-calculator"]
