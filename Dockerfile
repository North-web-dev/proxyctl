FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/proxyctl ./cmd/proxyctl

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/proxyctl /usr/local/bin/proxyctl
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/proxyctl"]
