# Build
FROM golang:1.12 as build

WORKDIR /src
COPY . .

RUN go install -v ./cmd/ssh-bastion-server

# Target
FROM gcr.io/distroless/base
COPY --from=build /go/bin/ssh-bastion-server /
CMD ["/ssh-bastion-server"]
