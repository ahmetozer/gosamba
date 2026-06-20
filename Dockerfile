# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/gosamba ./cmd/gosamba

FROM scratch
COPY --from=build /out/gosamba /usr/local/bin/gosamba

# SMB over direct TCP. Binding :445 requires the container to run as root
# (the default) or with NET_BIND_SERVICE.
EXPOSE 445

ENTRYPOINT ["/usr/local/bin/gosamba"]
