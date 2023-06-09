FROM golang:1.17-alpine AS helper-builder
RUN apk add build-base git
WORKDIR /service
RUN git clone -b upgrade-helper https://github.com/marcosdy/spiffe-helper.git .
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper
