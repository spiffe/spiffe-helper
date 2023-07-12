FROM golang:1.17-alpine AS spiffe-helper
COPY ./ /service/
WORKDIR /service
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper
