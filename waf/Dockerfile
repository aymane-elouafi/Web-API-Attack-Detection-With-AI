# Build stage: compile the Coraza proxy (needs Go, so we do it inside Docker)
FROM golang:1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /waf-proxy .

# Final stage: just the static binary, nothing else
FROM scratch
COPY --from=build /waf-proxy /waf-proxy
USER 65534:65534
ENTRYPOINT ["/waf-proxy"]
