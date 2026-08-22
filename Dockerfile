# REGISTRY selects where base images are pulled from. Defaults to public
# Docker Hub; override to a mirror/proxy-cache prefix, e.g.
#   --build-arg REGISTRY=registry.starnix.net/docker/library
ARG REGISTRY=docker.io/library

FROM ${REGISTRY}/golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM ${REGISTRY}/alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/web ./web
COPY --from=builder /app/config.yaml ./

EXPOSE 8080

CMD ["./main"]