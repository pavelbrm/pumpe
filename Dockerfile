FROM golang:1.23 AS builder

# Override toolchain directive in go.mod, to ensure the image's Go version is used.
# The official Go Dockerfiles already do this, but it's better to be explicit.
# https://github.com/docker-library/golang/issues/472
ENV GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends tor

WORKDIR /src

COPY . ./

RUN --mount=type=cache,target=/go/pkg/mod go mod download
ENV GOCACHE=/go/pkg/mod

RUN --mount=type=cache,target=/go/pkg/mod make build

USER nobody
EXPOSE 8080

CMD ["bin/pumpe"]
