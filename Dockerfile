FROM golang

WORKDIR /build
COPY . /build
RUN CGO_ENABLED=0 go build -o spiffe-helper ./cmd/spiffe-helper

FROM scratch
COPY --from=0 /build/spiffe-helper /spiffe-helper
ENTRYPOINT ["/spiffe-helper"]
CMD ["-config", "/etc/spiffe-helper.conf"]
