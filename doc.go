// Package acme is a pure-Go (CGO-free), MRI-faithful reimplementation of the
// surface of Ruby's acme-client gem — the ACME / Let's Encrypt protocol client.
//
// It mirrors the ergonomics of Acme::Client while delegating the ACME/JWS
// protocol itself to the standard, pure-Go golang.org/x/crypto/acme client, so
// no part of the RFC 8555 wire protocol is reimplemented here.
//
// The Ruby object graph is reproduced with idiomatic Go types:
//
//	client, _  := acme.NewClient(accountKey, directoryURL)
//	account, _ := client.NewAccount(ctx, []string{"mailto:me@example.com"}, true)
//	order, _   := client.NewOrder(ctx, []string{"example.com"})
//	authzs, _  := order.Authorizations(ctx)
//	chal       := authzs[0].HTTP01()
//	ka, _      := chal.KeyAuthorization()      // token.thumbprint to serve
//	_ = chal.RequestValidation(ctx)            // ask the CA to validate
//	csr, _     := acme.NewCSR(certKey, "example.com")
//	_ = order.Finalize(ctx, csr)
//	pem, _     := order.Certificate(ctx)       // PEM certificate chain
//
// The ACME transport is a host seam: an [*http.Client] can be injected with
// [WithHTTPClient], and the retry policy with [WithRetryBackoff], so the whole
// flow runs against an in-process mock ACME server with no live network and no
// real Let's Encrypt.
//
// Problem documents returned by the CA are mapped onto an error tree rooted at
// [*Error], with [*Unauthorized], [*RateLimited], [*BadNonce] and [*Malformed]
// mirroring the Acme::Client::Error subclasses.
package acme
