# Stage 1: Builder
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/main /app/main.go

# Stage 2: Runner
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080

# Command to run the application when the container starts
CMD ["./main"]
