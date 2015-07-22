# Go Keyless

[![Build Status](https://travis-ci.org/cloudflare/gokeyless.png?branch=master)](https://travis-ci.org/cloudflare/gokeyless)
[![Coverage Status](https://coveralls.io/repos/cloudflare/gokeyless/badge.svg?branch=master)](https://coveralls.io/r/cloudflare/gokeyless?branch=master)
[![GoDoc](https://godoc.org/github.com/cloudflare/gokeyless?status.png)](https://godoc.org/github.com/cloudflare/gokeyless)
## Keyless SSL implementation in Go

CFSSL is an implementation CloudFlare's [Keyless SSL](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/) Protocol in Go. It is provided as
an upgrade to the previous [C implementation](https://github.com/cloudflare/keyless). **NOTE: CURRENTLY IN ALPHA TESTING**

Note that certain linux distributions have certain algorithms removed
(RHEL-based distributions in particular), so the golang from the
official repositories will not work. Users of these distributions should
[install go manually](golang.org) to install Go Keyless.

### Installation

Installation requires a [working Go
installation](http://golang.org/doc/install) and a properly set `GOPATH`.

```
$ go get -u github.com/cloudflare/gokeyless/...
```