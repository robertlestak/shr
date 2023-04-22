FROM golang:1.19 AS builder

ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -ldflags="-X 'main.Version=${VERSION}'" -o /bin/shr cmd/shr/*.go

FROM debian:bullseye-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /bin/shr /bin/shr

ENTRYPOINT ["/bin/shr"]