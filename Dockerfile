# syntax=docker/dockerfile:1

FROM golang:1.25 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go *.txt ./
COPY static/ static/

RUN CGO_ENABLED=0 GOOS=linux go build -o /docker-website

# # Run the tests in the container
# FROM build-stage AS run-test-stage
# RUN go test -v ./...

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

COPY --from=build-stage /docker-website /docker-website

EXPOSE 8090

USER nonroot:nonroot

ENTRYPOINT ["/docker-website"]
CMD ["-https-only"]
