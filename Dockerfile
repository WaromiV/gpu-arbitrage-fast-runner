FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w -buildid=' -o /runner .

FROM ubuntu:24.04
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /runner /usr/local/bin/prl-runner
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/prl-runner"]
