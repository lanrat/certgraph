# build stage
FROM golang:alpine AS build-env
RUN apk update && apk add --no-cache make git

# Accept VERSION as a build argument
ARG VERSION
ENV VERSION=${VERSION}

WORKDIR /go/app/
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make

# final stage
FROM alpine

COPY --from=build-env /go/app/certgraph /bin/

USER 1000

ENTRYPOINT [ "certgraph" ]