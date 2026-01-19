FROM golang:alpine AS build
LABEL maintainer="team-core@elvia.no"

WORKDIR /app

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN addgroup nobody --gid 65534 && \
    adduser nobody --uid 65534 \
        --ingroup application-group \
        --disabled-password

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .
RUN go build -o ./out/executable .


FROM scratch
LABEL maintainer="team-core@elvia.no"

COPY --from=build /app/out/executable /executable
COPY --from=build /etc/passwd /etc/passwd

USER nobody:nobody

EXPOSE 8080

ENTRYPOINT ["/executable"]
