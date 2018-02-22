BUILD_DEPS := go

NAME := gokeyless
VENDOR := "CloudFlare"
LICENSE := "See License File"
URL := "https://github.com/cloudflare/gokeyless"
DESCRIPTION="A Go implementation of the keyless server protocol"
VERSION := $(shell git describe --tags --always --dirty=-dev)
LDFLAGS := "-X main.version=$(VERSION)"

DESTDIR                      := build
PREFIX                       := usr/local
INSTALL_BIN                  := $(DESTDIR)/$(PREFIX)/bin
INIT_PREFIX                  := $(DESTDIR)/etc/init.d
SYSTEMD_PREFIX               := $(DESTDIR)/lib/systemd/system
CONFIG_PREFIX                := $(DESTDIR)/etc/keyless

ARCH := amd64
DEB_PACKAGE := $(NAME)_$(VERSION)_$(ARCH).deb
RPM_PACKAGE := $(NAME)-$(VERSION).$(ARCH).rpm

.PHONY: all
all: $(DEB_PACKAGE) $(RPM_PACKAGE)

.PHONY: install-config
install-config:
	@mkdir -p $(INSTALL_BIN)
	@mkdir -p $(CONFIG_PREFIX)/keys
	@chmod 700 $(CONFIG_PREFIX)/keys
	@mkdir -p $(INIT_PREFIX)
	@mkdir -p $(SYSTEMD_PREFIX)
	@install -m755 pkg/gokeyless.sysv $(INIT_PREFIX)/gokeyless
	@install -m755 pkg/gokeyless.service $(SYSTEMD_PREFIX)/gokeyless.service
	@install -m644 pkg/keyless_cacert.pem $(CONFIG_PREFIX)/keyless_cacert.pem
	@install -m644 pkg/default.pem $(CONFIG_PREFIX)/default.pem
	@install -m400 pkg/default-key.pem $(CONFIG_PREFIX)/default-key.pem
	@install -m400 pkg/testing-ecdsa.key $(CONFIG_PREFIX)/keys/testing-ecdsa.key
	@install -m400 pkg/testing-rsa.key $(CONFIG_PREFIX)/keys/testing-rsa.key

$(INSTALL_BIN)/$(NAME): | install-config
	@GOOS=linux GOARCH=$(ARCH) go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(NAME)/...

.PHONY: clean
clean:
	@$(RM) -r $(DESTDIR)
	@$(RM) $(DEB_PACKAGE)
	@$(RM) $(RPM_PACKAGE)

FPM = fpm -C $(DESTDIR) \
	-n $(NAME) \
	-a $(ARCH) \
	-s dir \
	-v $(VERSION) \
	--url $(URL) \
	--description $(DESCRIPTION) \
	--vendor $(VENDOR) \
	--license $(LICENSE) \

$(DEB_PACKAGE): | $(INSTALL_BIN)/$(NAME) install-config
	@$(FPM) \
	-t deb \
	--before-install pkg/debian/before-install.sh \
	--before-remove  pkg/debian/before-remove.sh \
	--after-install  pkg/debian/after-install.sh \
	--deb-compression bzip2 \
	--deb-user root --deb-group root \
	.

$(RPM_PACKAGE): | $(INSTALL_BIN)/$(NAME) install-config
	@$(FPM) \
	-t rpm \
	--rpm-os linux \
	--before-install pkg/centos/before-install.sh \
	--before-remove  pkg/centos/before-remove.sh \
	--after-install  pkg/centos/after-install.sh \
	--rpm-use-file-permissions \
	--rpm-user root --rpm-group root \
	.

.PHONY: dev
dev: gokeyless
gokeyless: $(shell find . -type f -name '*.go')
	go build -ldflags "-X main.version=dev" -o $@ ./cmd/gokeyless/...
