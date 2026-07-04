# acme — go-ruby-acme

![go-ruby-acme/acme](https://raw.githubusercontent.com/go-ruby-acme/brand/main/social/go-ruby-acme-acme.png)

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ruby-acme/acme.svg)](https://pkg.go.dev/github.com/go-ruby-acme/acme)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![CI](https://github.com/go-ruby-acme/acme/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ruby-acme/acme/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the surface of Ruby's
[`acme-client`](https://github.com/unixcharles/acme-client) gem** — the ACME /
Let's Encrypt (RFC 8555) protocol client. It mirrors the ergonomics of
`Acme::Client` — accounts, orders, authorizations, challenges, finalization and
certificate download — while delegating the ACME/JWS wire protocol itself to the
standard, pure-Go [`golang.org/x/crypto/acme`](https://pkg.go.dev/golang.org/x/crypto/acme)
client, so **no part of RFC 8555 is reimplemented here**.

It is the ACME backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-jwt](https://github.com/go-ruby-jwt/jwt) and
[go-ruby-oauth2](https://github.com/go-ruby-oauth2/oauth2).

## Surface

The Ruby object graph is reproduced with idiomatic Go types:

- **Client** — `NewClient(privateKey, directory)` ≙ `Acme::Client.new(private_key:, directory:)`
- **Account** — `NewAccount(ctx, contact, tosAgreed)` ≙ `#new_account`, `Account(ctx)` for lookup
- **Order** — `NewOrder(ctx, identifiers)` ≙ `#new_order`; `Order#Authorizations`,
  `#Finalize(csr)`, `#Certificate` (PEM chain), `#Status`, `#Reload`
- **Authorization** — `#Challenges`, `#HTTP01` / `#DNS01` / `#TLSALPN01`, `#Domain`, `#Status`
- **Challenge** — `#KeyAuthorization` (`token.thumbprint`), `#RequestValidation`, `#Status`, `#Error`, `#Reload`
- **Errors** — an error tree rooted at `*Error` with `*Unauthorized`, `*RateLimited`,
  `*BadNonce` and `*Malformed`, mapping ACME problem documents onto the
  `Acme::Client::Error` subclasses

## Usage

```go
import "github.com/go-ruby-acme/acme"

client, _  := acme.NewClient(accountKey, "https://acme-v02.api.letsencrypt.org/directory")
account, _ := client.NewAccount(ctx, []string{"mailto:me@example.com"}, true)
order, _   := client.NewOrder(ctx, []string{"example.com"})

authzs, _ := order.Authorizations(ctx)
chal      := authzs[0].HTTP01()
ka, _     := chal.KeyAuthorization()   // serve at /.well-known/acme-challenge/<token>
_ = chal.RequestValidation(ctx)

csr, _ := acme.NewCSR(certKey, "example.com")
_ = order.Finalize(ctx, csr)
pemChain, _ := order.Certificate(ctx)
```

## Transport seam

The ACME transport is injectable. `WithHTTPClient` swaps the `*http.Client`
(the whole flow runs against an in-process mock ACME server with no live
network) and `WithRetryBackoff` tunes the retry policy. The test suite drives
the full account → order → authz → http-01 → finalize → certificate flow, plus
the `badNonce` retry, rate-limit, unauthorized and invalid-challenge error
paths, against a mock CA — deterministic, and with no real Let's Encrypt.

## Tests & coverage

`go test ./...` runs the full flow against the mock ACME server. The CI gate
enforces **100% statement coverage** under `-race` and builds/tests on all six
64-bit Go targets — `amd64`, `arm64`, `riscv64`, `loong64`, `ppc64le`, `s390x`
(big-endian).

## License

BSD-3-Clause. Copyright (c) the go-ruby-acme/acme authors.
