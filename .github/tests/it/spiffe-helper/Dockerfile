FROM golang:1.21-alpine AS spiffe-helper
COPY ./ /service/
WORKDIR /service
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper
RUN go build -tags netgo -a -v -o /service/simple-plugin ./examples/plugin/plugin.go
