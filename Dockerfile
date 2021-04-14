FROM golang:1.15.11-alpine3.12 as build

RUN mkdir /cert-wizard
WORKDIR /cert-wizard
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=master
RUN CGO_ENABLED=0 go build -o cert-wizard . 

FROM scratch
COPY --from=build /cert-wizard/cert-wizard /cert-wizard
EXPOSE 3001
ENTRYPOINT ["/cert-wizard"]
