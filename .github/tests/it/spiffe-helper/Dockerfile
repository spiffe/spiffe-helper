FROM golang:1.22.3-alpine AS spiffe-helper
COPY ./ /service/
WORKDIR /service
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper
