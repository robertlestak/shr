FROM golang:1.19 AS builder

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o /bin/shr cmd/shr/*.go

FROM debian:bullseye-slim AS runner

COPY --from=builder /bin/shr /bin/shr

ENTRYPOINT ["/bin/shr"]