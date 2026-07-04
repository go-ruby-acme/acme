package acme_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-ruby-acme/acme"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

// noRetry disables the transport's retry loop so injected 4xx/429 problems
// surface to the caller immediately (and deterministically).
func noRetry(int, *http.Request, *http.Response) time.Duration { return 0 }

func newTestClient(t *testing.T, m *mockACME, opts ...acme.Option) *acme.Client {
	t.Helper()
	all := append([]acme.Option{acme.WithHTTPClient(m.srv.Client())}, opts...)
	c, err := acme.NewClient(newKey(t), m.url("/directory"), all...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestHappyPath drives the complete acme-client flow against the mock CA:
// account -> order -> authz -> http-01 challenge -> finalize -> cert chain.
func TestHappyPath(t *testing.T) {
	m := newMockACME(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	acct, err := c.NewAccount(ctx, []string{"mailto:admin@example.com"}, true)
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if acct.Status != "valid" || acct.URL == "" || len(acct.Contact) != 1 {
		t.Fatalf("unexpected account: %+v", acct)
	}

	order, err := c.NewOrder(ctx, []string{"example.com"})
	if err != nil {
		t.Fatalf("NewOrder: %v", err)
	}
	if order.Status() != "pending" || order.URL() == "" {
		t.Fatalf("unexpected order: status=%q url=%q", order.Status(), order.URL())
	}
	if got := order.Identifiers(); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("identifiers = %v", got)
	}

	authzs, err := order.Authorizations(ctx)
	if err != nil {
		t.Fatalf("Authorizations: %v", err)
	}
	if len(authzs) != 1 {
		t.Fatalf("want 1 authz, got %d", len(authzs))
	}
	az := authzs[0]
	if az.Domain() != "example.com" || az.URL() == "" || az.Wildcard() || az.Status() != "valid" {
		t.Fatalf("unexpected authz: %+v", az)
	}
	if len(az.Challenges()) != 3 {
		t.Fatalf("want 3 challenges, got %d", len(az.Challenges()))
	}

	chal := az.HTTP01()
	if chal == nil || chal.Type() != acme.ChallengeHTTP01 {
		t.Fatalf("no http-01 challenge: %+v", chal)
	}
	if az.DNS01() == nil || az.TLSALPN01() == nil {
		t.Fatal("missing dns-01/tls-alpn-01 challenge")
	}
	if chal.Token() == "" || chal.URL() == "" {
		t.Fatalf("bad challenge token/url")
	}
	ka, err := chal.KeyAuthorization()
	if err != nil {
		t.Fatalf("KeyAuthorization: %v", err)
	}
	if !strings.HasPrefix(ka, chal.Token()+".") {
		t.Fatalf("key authorization %q not token.thumbprint", ka)
	}
	if err := chal.RequestValidation(ctx); err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if chal.Status() != "valid" || chal.Error() != nil {
		t.Fatalf("challenge status=%q err=%v", chal.Status(), chal.Error())
	}
	if err := chal.Reload(ctx); err != nil {
		t.Fatalf("Challenge.Reload: %v", err)
	}

	if err := order.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	csr, err := acme.NewCSR(newKey(t), "example.com", "www.example.com")
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}
	if err := order.Finalize(ctx, csr); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if order.Status() != "valid" {
		t.Fatalf("order status after finalize = %q", order.Status())
	}
	pemChain, err := order.Certificate(ctx)
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if strings.Count(pemChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("expected 2-cert chain, got:\n%s", pemChain)
	}
}

// TestMissingChallengeType verifies the typed accessors return nil when the CA
// does not offer that challenge.
func TestMissingChallengeType(t *testing.T) {
	m := newMockACME(t)
	m.onlyHTTP01 = true
	c := newTestClient(t, m)
	ctx := context.Background()
	if _, err := c.NewAccount(ctx, nil, true); err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	order, err := c.NewOrder(ctx, []string{"example.com"})
	if err != nil {
		t.Fatalf("NewOrder: %v", err)
	}
	authzs, err := order.Authorizations(ctx)
	if err != nil {
		t.Fatalf("Authorizations: %v", err)
	}
	az := authzs[0]
	if az.HTTP01() == nil {
		t.Fatal("http-01 should be present")
	}
	if az.DNS01() != nil || az.TLSALPN01() != nil {
		t.Fatal("dns-01/tls-alpn-01 should be absent")
	}
}

// TestAccountLookup covers the existing-account lookup path.
func TestAccountLookup(t *testing.T) {
	m := newMockACME(t)
	c := newTestClient(t, m)
	acct, err := c.Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if acct.URL == "" {
		t.Fatal("empty account URL")
	}
}

// TestBadNonceRetry verifies a transient badNonce is transparently retried and
// the flow still succeeds (retries enabled with a tiny backoff).
func TestBadNonceRetry(t *testing.T) {
	m := newMockACME(t)
	m.badNonceOnce.Store(true)
	fast := func(int, *http.Request, *http.Response) time.Duration { return time.Millisecond }
	c := newTestClient(t, m, acme.WithRetryBackoff(fast))
	if _, err := c.NewAccount(context.Background(), []string{"mailto:a@b.c"}, true); err != nil {
		t.Fatalf("NewAccount should succeed after badNonce retry: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		setup func(m *mockACME)
		check func(t *testing.T, err error)
	}{
		{
			name:  "unauthorized",
			setup: func(m *mockACME) { m.failAccount = http.StatusForbidden; m.accountProb = urnPrefix + "unauthorized" },
			check: func(t *testing.T, err error) {
				var e *acme.Unauthorized
				if !errors.As(err, &e) {
					t.Fatalf("want *Unauthorized, got %T: %v", err, err)
				}
				if e.Problem.StatusCode != http.StatusForbidden {
					t.Fatalf("status=%d", e.Problem.StatusCode)
				}
				var base *acme.Error
				if !errors.As(err, &base) {
					t.Fatal("Unauthorized should unwrap to *Error")
				}
			},
		},
		{
			name:  "malformed",
			setup: func(m *mockACME) { m.failAccount = http.StatusBadRequest; m.accountProb = urnPrefix + "malformed" },
			check: func(t *testing.T, err error) {
				var e *acme.Malformed
				if !errors.As(err, &e) {
					t.Fatalf("want *Malformed, got %T", err)
				}
			},
		},
		{
			name:  "badNonce",
			setup: func(m *mockACME) { m.failAccount = http.StatusBadRequest; m.accountProb = urnPrefix + "badNonce" },
			check: func(t *testing.T, err error) {
				var e *acme.BadNonce
				if !errors.As(err, &e) {
					t.Fatalf("want *BadNonce, got %T", err)
				}
			},
		},
		{
			name:  "rateLimited",
			setup: func(m *mockACME) { m.rateLimitAcct = true },
			check: func(t *testing.T, err error) {
				var e *acme.RateLimited
				if !errors.As(err, &e) {
					t.Fatalf("want *RateLimited, got %T", err)
				}
				if e.RetryAfter != 5*time.Second {
					t.Fatalf("RetryAfter=%v want 5s", e.RetryAfter)
				}
			},
		},
		{
			name:  "unknown-with-colon",
			setup: func(m *mockACME) { m.failAccount = http.StatusBadRequest; m.accountProb = urnPrefix + "serverInternal" },
			check: func(t *testing.T, err error) {
				var e *acme.Error
				if !errors.As(err, &e) {
					t.Fatalf("want *Error, got %T", err)
				}
				if !strings.HasSuffix(e.ProblemType, "serverInternal") {
					t.Fatalf("problem=%q", e.ProblemType)
				}
			},
		},
		{
			name:  "unknown-no-colon",
			setup: func(m *mockACME) { m.failAccount = http.StatusBadRequest; m.accountProb = "weird" },
			check: func(t *testing.T, err error) {
				var e *acme.Error
				if !errors.As(err, &e) {
					t.Fatalf("want *Error, got %T", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockACME(t)
			tc.setup(m)
			c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
			_, err := c.NewAccount(ctx, []string{"mailto:a@b.c"}, true)
			if err == nil {
				t.Fatal("expected error")
			}
			tc.check(t, err)
		})
	}
}

// TestInvalidChallenge verifies a failed challenge surfaces status "invalid"
// and a mapped error via Challenge#error.
func TestInvalidChallenge(t *testing.T) {
	m := newMockACME(t)
	m.failChallenge = true
	c := newTestClient(t, m)
	ctx := context.Background()
	if _, err := c.NewAccount(ctx, nil, true); err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	order, err := c.NewOrder(ctx, []string{"example.com"})
	if err != nil {
		t.Fatalf("NewOrder: %v", err)
	}
	authzs, err := order.Authorizations(ctx)
	if err != nil {
		t.Fatalf("Authorizations: %v", err)
	}
	chal := authzs[0].HTTP01()
	if err := chal.RequestValidation(ctx); err != nil {
		t.Fatalf("RequestValidation transport: %v", err)
	}
	if chal.Status() != "invalid" {
		t.Fatalf("status=%q want invalid", chal.Status())
	}
	var un *acme.Unauthorized
	if !errors.As(chal.Error(), &un) {
		t.Fatalf("challenge error = %T %v", chal.Error(), chal.Error())
	}
}

// TestMethodErrorPaths exercises the mapError branch of each order/authz/
// challenge method by injecting an endpoint failure.
func TestMethodErrorPaths(t *testing.T) {
	ctx := context.Background()

	newOrder := func(t *testing.T, m *mockACME) (*acme.Client, *acme.Order) {
		c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		o, err := c.NewOrder(ctx, []string{"example.com"})
		if err != nil {
			t.Fatalf("NewOrder: %v", err)
		}
		return c, o
	}

	t.Run("NewOrder", func(t *testing.T) {
		m := newMockACME(t)
		m.failNewOrder = true
		c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		if _, err := c.NewOrder(ctx, []string{"example.com"}); err == nil {
			t.Fatal("expected NewOrder error")
		}
	})

	t.Run("Account", func(t *testing.T) {
		m := newMockACME(t)
		m.failAccount = http.StatusBadRequest
		m.accountProb = urnPrefix + "malformed"
		c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
		if _, err := c.Account(ctx); err == nil {
			t.Fatal("expected Account error")
		}
	})

	t.Run("Authorizations", func(t *testing.T) {
		m := newMockACME(t)
		_, o := newOrder(t, m)
		m.failAuthz = true
		if _, err := o.Authorizations(ctx); err == nil {
			t.Fatal("expected Authorizations error")
		}
	})

	t.Run("Reload", func(t *testing.T) {
		m := newMockACME(t)
		_, o := newOrder(t, m)
		m.failOrderGet = true
		if err := o.Reload(ctx); err == nil {
			t.Fatal("expected Reload error")
		}
	})

	t.Run("Finalize", func(t *testing.T) {
		m := newMockACME(t)
		_, o := newOrder(t, m)
		m.failFinalize = true
		csr, _ := acme.NewCSR(newKey(t), "example.com")
		if err := o.Finalize(ctx, csr); err == nil {
			t.Fatal("expected Finalize error")
		}
	})

	t.Run("RequestValidation", func(t *testing.T) {
		m := newMockACME(t)
		_, o := newOrder(t, m)
		authzs, err := o.Authorizations(ctx)
		if err != nil {
			t.Fatalf("Authorizations: %v", err)
		}
		m.failChallengeReq = true
		if err := authzs[0].HTTP01().RequestValidation(ctx); err == nil {
			t.Fatal("expected RequestValidation error")
		}
	})

	t.Run("ChallengeReload", func(t *testing.T) {
		m := newMockACME(t)
		_, o := newOrder(t, m)
		authzs, err := o.Authorizations(ctx)
		if err != nil {
			t.Fatalf("Authorizations: %v", err)
		}
		chal := authzs[0].HTTP01()
		m.failChallengeReq = true
		if err := chal.Reload(ctx); err == nil {
			t.Fatal("expected Challenge.Reload error")
		}
	})
}

// TestCertificateFetchPaths covers Certificate downloading the chain (rather
// than reusing a Finalize cache), including the reload-for-cert-url path and
// the failure branches.
func TestCertificateFetchPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("fetch-after-reload", func(t *testing.T) {
		m := newMockACME(t)
		c := newTestClient(t, m)
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		o, err := c.NewOrder(ctx, []string{"example.com"})
		if err != nil {
			t.Fatalf("NewOrder: %v", err)
		}
		// Order has no CertURL yet; Certificate must reload (mock reports the
		// order valid with a certificate URL) then download the chain.
		pemChain, err := o.Certificate(ctx)
		if err != nil {
			t.Fatalf("Certificate: %v", err)
		}
		if !strings.Contains(pemChain, "BEGIN CERTIFICATE") {
			t.Fatal("no certificate returned")
		}
	})

	t.Run("not-ready", func(t *testing.T) {
		m := newMockACME(t)
		m.challengeStatus = "pending" // GET order stays pending -> no cert URL
		m.orderNoCertURL = true
		c := newTestClient(t, m)
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		o, err := c.NewOrder(ctx, []string{"example.com"})
		if err != nil {
			t.Fatalf("NewOrder: %v", err)
		}
		_, err = o.Certificate(ctx)
		if err == nil {
			t.Fatal("expected not-ready error")
		}
		var e *acme.Error
		if !errors.As(err, &e) || !strings.Contains(e.Detail, "not ready") {
			t.Fatalf("want not-ready *Error, got %T %v", err, err)
		}
	})

	t.Run("reload-error", func(t *testing.T) {
		m := newMockACME(t)
		c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		o, err := c.NewOrder(ctx, []string{"example.com"})
		if err != nil {
			t.Fatalf("NewOrder: %v", err)
		}
		m.failOrderGet = true
		if _, err := o.Certificate(ctx); err == nil {
			t.Fatal("expected Certificate reload error")
		}
	})

	t.Run("fetch-error", func(t *testing.T) {
		m := newMockACME(t)
		c := newTestClient(t, m, acme.WithRetryBackoff(noRetry))
		if _, err := c.NewAccount(ctx, nil, true); err != nil {
			t.Fatalf("NewAccount: %v", err)
		}
		o, err := c.NewOrder(ctx, []string{"example.com"})
		if err != nil {
			t.Fatalf("NewOrder: %v", err)
		}
		// Reload succeeds and yields a CertURL, but the cert download fails.
		m.failCert = true
		if _, err := o.Certificate(ctx); err == nil {
			t.Fatal("expected Certificate fetch error")
		}
	})
}

// TestTransportErrorNotMapped verifies a non-ACME transport error passes
// through mapError unchanged (the errors.As-false branch).
func TestTransportErrorNotMapped(t *testing.T) {
	// A directory URL with no server yields a connection error, not an *Error.
	c, err := acme.NewClient(newKey(t), "http://127.0.0.1:1/directory")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.NewAccount(context.Background(), nil, true)
	if err == nil {
		t.Fatal("expected transport error")
	}
	var e *acme.Error
	if errors.As(err, &e) {
		t.Fatalf("transport error should not map to *Error: %v", err)
	}
}

// TestKeyAuthorizationError covers the error branch of KeyAuthorization by
// using an unsupported (ed25519) account key.
func TestKeyAuthorizationError(t *testing.T) {
	m := newMockACME(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	c, err := acme.NewClient(edSigner{priv}, m.url("/directory"), acme.WithHTTPClient(m.srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ch := acme.NewChallengeForTest(c, "tok")
	if _, err := ch.KeyAuthorization(); err == nil {
		t.Fatal("expected KeyAuthorization error for unsupported key")
	}
}

// edSigner adapts an ed25519 key to crypto.Signer with an unsupported public
// key type (ed25519 is not an RFC 7518 JWS key), so JWK thumbprinting fails.
type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) Public() crypto.PublicKey { return s.priv.Public() }
func (s edSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(s.priv, digest), nil
}

// TestErrorStrings covers the Error() formatters on the error tree.
func TestErrorStrings(t *testing.T) {
	withDetail := &acme.Error{ProblemType: "urn:x:malformed", Detail: "boom", StatusCode: 400}
	if got := withDetail.Error(); !strings.Contains(got, "boom") || !strings.Contains(got, "400") {
		t.Fatalf("Error() = %q", got)
	}
	noDetail := &acme.Error{ProblemType: "urn:x:malformed", StatusCode: 500}
	if got := noDetail.Error(); strings.Contains(got, ":") && strings.Contains(got, "boom") {
		t.Fatalf("Error() = %q", got)
	}
	if got := noDetail.Error(); !strings.Contains(got, "500") {
		t.Fatalf("Error() = %q", got)
	}
	subs := []error{
		&acme.Unauthorized{Problem: withDetail},
		&acme.Malformed{Problem: withDetail},
		&acme.BadNonce{Problem: withDetail},
		&acme.RateLimited{Problem: withDetail, RetryAfter: time.Second},
	}
	for _, e := range subs {
		if !strings.Contains(e.Error(), "boom") {
			t.Fatalf("%T.Error() = %q", e, e.Error())
		}
		if !errors.Is(e, errors.Unwrap(e)) {
			// smoke check Unwrap returns non-nil
		}
		if errors.Unwrap(e) == nil {
			t.Fatalf("%T.Unwrap() is nil", e)
		}
	}
}
