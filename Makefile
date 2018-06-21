NAME := gokeyless
VENDOR := "Cloudflare"
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
CONFIG_PATH                  := etc/keyless
CONFIG_PREFIX                := $(DESTDIR)/$(CONFIG_PATH)

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
	@install -m644 pkg/keyless_cacert.pem $(CONFIG_PREFIX)/keyless_cacert.pem
	@install -m755 pkg/gokeyless.sysv $(INIT_PREFIX)/gokeyless
	@install -m755 pkg/gokeyless.service $(SYSTEMD_PREFIX)/gokeyless.service
	@install -m600 pkg/gokeyless.yaml $(CONFIG_PREFIX)/gokeyless.yaml

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
	--before-remove pkg/debian/before-remove.sh \
	--after-install pkg/debian/after-install.sh \
	--config-files /$(CONFIG_PATH)/gokeyless.yaml \
	--deb-compression bzip2 \
	--deb-user root --deb-group root \
	.

$(RPM_PACKAGE): | $(INSTALL_BIN)/$(NAME) install-config
	@$(FPM) \
	-t rpm \
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
	go build -ldflags "-X main.version=dev" -o $@ ./cmd/gokeyless/...

.PHONY: install-dev
install-dev: install-config
	@install -m644 tests/testdata/default.pem $(CONFIG_PREFIX)/default.pem
	@install -m400 tests/testdata/default-key.pem $(CONFIG_PREFIX)/default-key.pem
	@install -m400 tests/testdata/testing-ecdsa.key $(CONFIG_PREFIX)/keys/testing-ecdsa.key
	@install -m400 tests/testdata/testing-rsa.key $(CONFIG_PREFIX)/keys/testing-rsa.key

SOFTHSM_TOKENS_PATH          := $(DESTDIR)/var/lib/softhsm/tokens
SOFTHSM_CONFIG_PATH          := $(DESTDIR)/etc

.PHONY: install-dev-softhsm
install-dev-softhsm: install-dev
	@mkdir -p  $(SOFTHSM_CONFIG_PATH)
	@mkdir -p  $(SOFTHSM_TOKENS_PATH)
	@chmod 700 $(SOFTHSM_TOKENS_PATH)
	@cp -r tests/testdata/tokens/*      $(SOFTHSM_TOKENS_PATH)
	@install -m644 tests/testdata/softhsm2.conf $(SOFTHSM_CONFIG_PATH)/softhsm2.conf
