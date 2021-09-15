FROM golang:alpine as builder

RUN apk add --no-cache make git gcc musl-dev

ENV REPOSITORY github.com/vulsio/go-msfdb
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && make install

FROM alpine:3.14

LABEL maintainer takuzoo3868

ENV LOGDIR /var/log/go-msfdb
ENV WORKDIR /go-msfdb

RUN apk add --no-cache ca-certificates git \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/go-msfdb /usr/local/bin/

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["go-msfdb"]
CMD ["--help"]
