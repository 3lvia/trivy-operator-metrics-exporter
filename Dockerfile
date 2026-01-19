FROM golang:alpine AS build
LABEL maintainer="team-core@elvia.no"

WORKDIR /app

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY main.go VERSION ./
COPY ./pkg ./pkg

RUN go build -o ./out/executable .


FROM scratch
LABEL maintainer="team-core@elvia.no"

COPY --from=build /app/out/executable /executable

USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/executable"]
