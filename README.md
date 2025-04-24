# Go Keyless

[![Go Test](https://github.com/cloudflare/gokeyless/actions/workflows/go.yml/badge.svg)](https://github.com/cloudflare/gokeyless/actions/workflows/go.yml)
[![GoDoc](https://pkg.go.dev/badge/github.com/cloudflare/gokeyless)](https://pkg.go.dev/github.com/cloudflare/gokeyless)
[![codecov](https://codecov.io/github/cloudflare/gokeyless/branch/master/graph/badge.svg?token=kcha1ub1Ju)](https://codecov.io/github/cloudflare/gokeyless)

Go Keyless is an implementation Cloudflare's [Keyless SSL](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/) Protocol in Go. It is provided as an upgrade to the previous [C implementation](https://github.com/cloudflare/keyless).

## Installing

### Package Installation

Instructions for installing Go Keyless from `.deb` and `.rpm` packages can be found at [https://pkg.cloudflare.com](https://pkg.cloudflare.com/). Packages and binaries are also available from [Github Releases](https://github.com/cloudflare/gokeyless/releases), with the caveat that there's no auto update mechanism built in.

## Key Management

The Keyless SSL server is a TLS server and therefore requires cryptographic keys. All requests are mutually authenticated, so both the client and the server need a TLS 1.2 compatible key pair. The client must present a client certificate that can be verified against the CA that the keyless server is configured to use. This process can be automated using a cloudflare Origin CA API Key - see the [documentation](https://developers.cloudflare.com/ssl/keyless-ssl/) for examples.

### Supported Key stores

### Directory

A directory containing private keys with a `.key` extension in either PEM or DER format

```yaml
private_key_stores:
    - dir: etc/private-keys/
```

Full instructions: https://developers.cloudflare.com/ssl/keyless-ssl/configuration/public-dns/#populate-keys

#### PKCS #11 Compatible HSM

Private keys can also be stored on a Hardware Security Module. Keyless can access such a key using a [PKCS #11 URI](https://tools.ietf.org/html/rfc7512) in the configuration file. Here are some examples of URIs for keys stored on various HSM providers:

```yaml
private_key_stores:
    - uri: pkcs11:token=SoftHSM2%20RSA%20Token;id=%03?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234
    - uri: pkcs11:token=accelerator;object=thaleskey?module-path=/opt/nfast/toolkits/pkcs11/libcknfast.so
    - uri: pkcs11:token=YubiKey%20PIV;id=%00?module-path=/usr/lib64/libykcs11.so&pin-value=123456&max-sessions=1
    - uri: pkcs11:token=SoftHSM2%20RSA%20Token;id=%03?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234
    - uri: pkcs11:token=elab2parN;id=%04?module-path=/usr/lib/libCryptoki2_64.so&pin-value=crypto1
```

Note you must provide exactly one of the `token`, `serial`, or `slot-id` attributes to identify the token.

Full instructions: https://developers.cloudflare.com/ssl/keyless-ssl/hardware-security-modules#communicating-using-pkcs11

#### Azure Key Vault or Managed HSM

_note: support added in [v1.6.4](https://github.com/cloudflare/gokeyless/releases/tag/v1.6.4)_

Private keys can also be stored in Azure's [key management offerings](https://docs.microsoft.com/en-us/azure/key-vault/keys/about-keys).

```yaml
private_key_stores:
    - uri: https://keyless-hsm-1.managedhsm.azure.net/keys/keyless-a/256400ae07e74327b5d233c15aea837
    - uri: https://keyless-vault-1.vault.azure.net/keys/keyless-b/d791e7f42b3a4f3ea8acc65014ea6a95
```

If gokeyless is running in a VM with Managed Services enabled, auth works out of the box. Otherwise, credentials can also be specified with an env var containing the path to a file. (env vars are defined [here](https://pkg.go.dev/github.com/Azure/go-autorest/autorest/azure/auth#pkg-constants))
The required roles are `/keys/read/action` and `/keys/sign/action`

Full instructions: https://developers.cloudflare.com/ssl/keyless-ssl/hardware-security-modules/azure-managed-hsm

#### Google Cloud KMS or Cloud HSM

_note: support added in [v1.6.4](https://github.com/cloudflare/gokeyless/releases/tag/v1.6.4)_

Private keys can also be stored in Google Cloud's [key management offerings](https://cloud.google.com/security-key-management)

```yaml
private_key_stores:
    - uri: projects/abc/locations/us-west1/keyRings/xyz/cryptoKeys/example-key/cryptoKeyVersions/3
```

[Application Default Credentials](https://cloud.google.com/docs/authentication/production#automatically) are supported, the required [IAM role](https://cloud.google.com/kms/docs/reference/permissions-and-roles) is `roles/cloudkms.signerVerifier`

Full instructions: https://developers.cloudflare.com/ssl/keyless-ssl/hardware-security-modules/google-cloud-hsm

## Running

The keyserver for Keyless SSL consists of a single binary file, `gokeyless`. When you run the binary, it will first check for a `gokeyless.yaml` file in the current working directory, falling back to the system wide file located at `/etc/keyless/gokeyless.yaml` (the default configuration file will be placed there if you install via one of the `.deb` or `.rpm` packages).

You should add your Cloudflare account details to the configuration file, and optionally customize the location of the private key directory. Most users should not need to modify the remaining defaults.

Each option can optionally be overridden via environment variables or command-line arguments. Run `gokeyless -h` to see the full list of available options.

## Running using Docker Image

A docker image is published that contains a built binary file and startup instruction for the `gokeyless` process.  An example of the usage of this docker file is in `docker-compose.example.yaml`

This examples shows how you may provide the same configuration options through environment variables and provide a mount with a directory for private keys instead of through a `gokeyless.yaml` file.

## Testing

Unit tests and benchmarks have been implemented for various parts of Go Keyless via `go test`. Most of the tests run out of the box, but some setup is necessary to run the HSM-related tests:

1. Follow https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2 to install SoftHSM2. On MacOS, the easiest is `brew isntall softhsm`
2. Copy the test tokens to the location of your SoftHSM2 token directory (commonly `/var/lib/softhsm/tokens`, but may vary):

```bash
cp -r tests/testdata/tokens/* /opt/homebrew/var/lib/softhsm/tokens/
```

1. The tests currently assume the SoftHSM2 library will be installed at `/usr/lib/softhsm/libsofthsm2.so`. If your system differs, `SOFTHSM_MODULE_DIR` env var can override that.

e.g. on MacOS with softhsm from brew:
`SOFTHSM_MODULE_DIR=/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so make test`

Note that if you need to run the tests without first configuring SoftHSM2 for some reason, you can use the `test-nohsm` target.

## License

See the LICENSE file for details. Note: the license for this project is not
'open source' as described in the [Open Source
Definition](http://opensource.org/osd).
