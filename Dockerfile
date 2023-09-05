FROM golang:1.21 as builder
WORKDIR /gokeyless
COPY . .
RUN env GOOS=linux GOARCH=amd64 make gokeyless

FROM golang:1.21
WORKDIR /gokeyless
COPY --from=builder /gokeyless/gokeyless gokeyless
ENTRYPOINT ["./gokeyless"]