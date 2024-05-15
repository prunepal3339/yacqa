FROM golang:1.22 as base

WORKDIR /app

#Copies everything from your root directory
COPY . .


#Installs Go dependencies
RUN go get 

RUN CGO_ENABLED=0 go build -o /godocker

FROM ubuntu:20.04

COPY --from=base /myapp /myapp

ENTRYPOINT [ "/myapp" ]