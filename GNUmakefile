.PHONY: \
	build \
	install \
	all \
	vendor \
	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	cov \
	clean \
	build-integration \
	clean-integration \
	fetch-rdb \
	fetch-redis \
	diff-server-rdb \
	diff-server-redis \
	diff-server-rdb-redis

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/takuzoo3868/go-msfdb/config.Version=$(VERSION)' \
	-X 'github.com/takuzoo3868/go-msfdb/config.Revision=$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go

all: build

build: main.go pretest fmt
	$(GO) build -ldflags "$(LDFLAGS)" -o go-msfdb $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	$(GO_OFF) get -u golang.org/x/lint/golint
	golint $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

BRANCH := $(shell git symbolic-ref --short HEAD)
build-integration:
	@ git stash save
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-msfdb.new
	git checkout $(shell git describe --tags --abbrev=0)
	@git reset --hard
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-msfdb.old
	git checkout $(BRANCH)
	-@ git stash apply stash@{0} && git stash drop stash@{0}

clean-integration:
	-pkill go-msfdb.old
	-pkill go-msfdb.new
	-rm integration/go-msfdb.old integration/go-msfdb.new integration/go-msfdb.old.sqlite3 integration/go-msfdb.new.sqlite3
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/go-msfdb.old fetch msfdb --dbpath=integration/go-msfdb.old.sqlite3
	integration/go-msfdb.new fetch msfdb --dbpath=integration/go-msfdb.new.sqlite3

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis

	integration/go-msfdb.old fetch msfdb --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/go-msfdb.new fetch msfdb --dbtype redis --dbpath "redis://127.0.0.1:6380/0"

diff-server-rdb:
	integration/go-msfdb.old server --dbpath=integration/go-msfdb.old.sqlite3 --port 1325 > /dev/null & 
	integration/go-msfdb.new server --dbpath=integration/go-msfdb.new.sqlite3 --port 1326 > /dev/null &
	@ python integration/diff_server_mode.py cves
	@ python integration/diff_server_mode.py edbs
	pkill go-msfdb.old 
	pkill go-msfdb.new

diff-server-redis:
	integration/go-msfdb.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null & 
	integration/go-msfdb.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null &
	@ python integration/diff_server_mode.py cves
	@ python integration/diff_server_mode.py edbs
	pkill go-msfdb.old 
	pkill go-msfdb.new

diff-server-rdb-redis:
	integration/go-msfdb.new server --dbpath=integration/go-msfdb.new.sqlite3 --port 1325 > /dev/null &
	integration/go-msfdb.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null &
	@ python integration/diff_server_mode.py cves
	@ python integration/diff_server_mode.py edbs
	pkill go-msfdb.new