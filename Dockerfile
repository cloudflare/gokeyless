FROM golang:1.21 as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM"

LABEL org.opencontainers.image.source = https://github.com/cloudflare/gokeyless
LABEL org.opencontainers.image.description = "Cloudflare's Gokeyless"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /gokeyless
COPY . .
RUN env GOOS=${TARGETOS} GOARCH=${TARGETARCH} make gokeyless

FROM golang:1.21
WORKDIR /gokeyless
COPY --from=builder /gokeyless/gokeyless gokeyless
ENTRYPOINT ["./gokeyless"]



