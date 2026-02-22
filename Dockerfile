FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /app .

FROM alpine:3.23
RUN apk --no-cache add ca-certificates
RUN adduser -D appuser
USER appuser
COPY --from=builder /app /usr/local/bin/app
EXPOSE 8080
CMD ["app"]
