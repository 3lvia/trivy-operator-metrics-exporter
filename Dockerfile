FROM golang:alpine AS build
LABEL maintainer="elvia@elvia.no"

WORKDIR /app

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN addgroup application-group --gid 1001 && \
    adduser application-user --uid 1001 \
        --ingroup application-group \
        --disabled-password

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .
RUN go build -o ./out/executable ./cmd/trivy-operator-metrics-exporter


FROM scratch
LABEL maintainer="elvia@elvia.no"

COPY --from=build /app/out/executable /executable
COPY --from=build /etc/passwd /etc/passwd

USER application-user

EXPOSE 8080

ENTRYPOINT ["/executable"]
