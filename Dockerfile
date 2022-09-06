#Build
FROM golang:alpine AS builder

WORKDIR /go/src/app

COPY ["go.mod", "go.sum", "./" ]
RUN go mod download

COPY . *.go ./

RUN go build -o ./bin/health-check ./cmd/health-check

## Deploy
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /usr/bin

COPY --from=builder /go/src/app/bin/health-check health-check

EXPOSE 8080
ENTRYPOINT /usr/bin/health-check 
