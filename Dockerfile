FROM golang:alpine as builder

RUN apk add --no-cache make git gcc musl-dev

ENV REPOSITORY github.com/takuzoo3868/go-msfdb
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && make install

FROM alpine:3.11

MAINTAINER takuzoo3868

ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls

RUN apk add --no-cache ca-certificates \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/go-msfdb /usr/local/bin/

VOLUME [$WORKDIR, $LOGDIR]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["go-msfdb"]
CMD ["--help"]