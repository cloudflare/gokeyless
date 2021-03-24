NAME := gokeyless
VENDOR := "Cloudflare"
LICENSE := "See License File"
URL := "https://github.com/cloudflare/gokeyless"
DESCRIPTION="A Go implementation of the keyless server protocol"
VERSION := $(shell git describe --tags --abbrev=0 | tr -d '[:alpha:]')
LDFLAGS := "-X main.version=$(VERSION)"

DESTDIR                      := build
PREFIX                       := usr/local
INSTALL_BIN                  := $(DESTDIR)/$(PREFIX)/bin
INIT_PREFIX                  := $(DESTDIR)/etc/init.d
SYSTEMD_PREFIX               := $(DESTDIR)/lib/systemd/system
CONFIG_PATH                  := etc/keyless
CONFIG_PREFIX                := $(DESTDIR)/$(CONFIG_PATH)

OS ?= linux
ARCH ?= amd64

# build without using the network
export GOPROXY := off
export GOFLAGS := -mod=vendor

.PHONY: all
all: package-deb package-rpm

.PHONY: install-config
install-config:
	@mkdir -p $(INSTALL_BIN)
	@mkdir -p $(CONFIG_PREFIX)/keys
	@chmod 700 $(CONFIG_PREFIX)/keys
	@mkdir -p $(INIT_PREFIX)
	@mkdir -p $(SYSTEMD_PREFIX)
	@install -m644 pkg/keyless_cacert.pem $(CONFIG_PREFIX)/keyless_cacert.pem
	@install -m755 pkg/gokeyless.sysv $(INIT_PREFIX)/gokeyless
	@install -m755 pkg/gokeyless.service $(SYSTEMD_PREFIX)/gokeyless.service
	@install -m600 pkg/gokeyless.yaml $(CONFIG_PREFIX)/gokeyless.yaml

$(INSTALL_BIN)/$(NAME): | install-config
	GOOS=$(OS) GOARCH=$(ARCH) go build -tags pkcs11 -ldflags $(LDFLAGS) -o $@ ./cmd/$(NAME)/...

.PHONY: clean
clean:
	$(RM) -r $(DESTDIR)
	$(RM) *.rpm *.deb

FPM = fpm -C $(DESTDIR) \
	-n $(NAME) \
	-a $(ARCH) \
	-s dir \
	-v $(VERSION) \
	--url $(URL) \
	--description $(DESCRIPTION) \
	--vendor $(VENDOR) \
	--license $(LICENSE) \

.PHONY: package-deb
package-deb: | $(INSTALL_BIN)/$(NAME) install-config
	$(FPM) \
	-t deb \
	-d libltdl7 \
	--before-install pkg/debian/before-install.sh \
	--before-remove pkg/debian/before-remove.sh \
	--after-install pkg/debian/after-install.sh \
	--config-files /$(CONFIG_PATH)/gokeyless.yaml \
	--deb-compression gz \
	--deb-user root --deb-group root \
	.

.PHONY: package-rpm
package-rpm: | $(INSTALL_BIN)/$(NAME) install-config
	$(FPM) \
	-t rpm \
	-d libtool-ltdl \
	--rpm-os linux \
	--before-install pkg/centos/before-install.sh \
	--before-remove pkg/centos/before-remove.sh \
	--after-install pkg/centos/after-install.sh \
	--config-files /$(CONFIG_PATH)/gokeyless.yaml \
	--rpm-use-file-permissions \
	--rpm-user root --rpm-group root \
	.

.PHONY: dev
dev: gokeyless
gokeyless: $(shell find . -type f -name '*.go')
	go build -tags pkcs11 -ldflags "-X main.version=dev" -o $@ ./cmd/gokeyless/...

.PHONY: vet
vet:
	go vet -tags pkcs11 ./...

.PHONY: lint
lint:
	for i in `go list ./... | grep -v /vendor/`; do golint $$i; done

.PHONY: test
test:
	GODEBUG=cgocheck=2 go test -tags pkcs11 -v -cover -race ./...
	GODEBUG=cgocheck=2 go test -tags pkcs11 -v -cover -race ./tests -args -softhsm2

.PHONY: test-nohsm
test-nohsm:
	GODEBUG=cgocheck=2 go test -v -cover -race ./...

.PHONY: test-trust
test-trust: gokeyless
	tests/trust-check.sh

.PHONY: benchmark-softhsm
benchmark-softhsm:
	go test -tags pkcs11 -v -race ./server -bench HSM -args -softhsm2

# GORELEASER_GITHUB_TOKEN=X make release-github
# token from https://github.com/settings/tokens/new
.PHONY: release-github
release-github:
	docker run --rm --privileged -v $(PWD):/go/tmp \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-w /go/tmp \
		--env GORELEASER_GITHUB_TOKEN \
		neilotoole/xcgo:latest goreleaser --rm-dist

