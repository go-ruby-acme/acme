package acme

import (
	"context"
	"crypto"
	"net/http"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Client is a pure-Go ACME client, mirroring Ruby's Acme::Client.
//
// It is constructed from an account private key and the CA's directory URL and
// is the entry point for account registration and order creation.
type Client struct {
	ac *xacme.Client
}

// Option configures a [Client] at construction time.
type Option func(*Client)

// WithHTTPClient injects the HTTP client used for every ACME request. This is
// the transport seam: tests point it at an in-process mock ACME server.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.ac.HTTPClient = hc }
}

// WithRetryBackoff installs a custom retry-backoff policy. Returning a
// non-positive duration disables further retries of a failed request. Mirrors
// the tunable retry behaviour exposed by the underlying transport.
func WithRetryBackoff(fn func(n int, r *http.Request, resp *http.Response) time.Duration) Option {
	return func(c *Client) { c.ac.RetryBackoff = fn }
}

// NewClient builds a [Client] from an account private key and a directory URL,
// mirroring Acme::Client.new(private_key:, directory:).
//
// privateKey must be an RSA or ECDSA key (per RFC 7518); directory is the CA's
// ACME directory endpoint.
func NewClient(privateKey crypto.Signer, directory string, opts ...Option) (*Client, error) {
	c := &Client{
		ac: &xacme.Client{
			Key:          privateKey,
			DirectoryURL: directory,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Account is a registered ACME account, mirroring the account object returned
// by Acme::Client#new_account.
type Account struct {
	// URL is the account resource URL (the KID used to sign later requests).
	URL string
	// Status is the account status, e.g. "valid".
	Status string
	// Contact is the list of contact URIs registered for the account.
	Contact []string
}

func newAccount(a *xacme.Account) *Account {
	return &Account{URL: a.URI, Status: a.Status, Contact: a.Contact}
}

// NewAccount registers a new account with the CA, mirroring
// Acme::Client#new_account(contact:, terms_of_service_agreed:).
//
// contact is a list of contact URIs (e.g. "mailto:me@example.com"); when
// termsOfServiceAgreed is true the client agrees to the CA's terms of service.
func (c *Client) NewAccount(ctx context.Context, contact []string, termsOfServiceAgreed bool) (*Account, error) {
	a, err := c.ac.Register(ctx, &xacme.Account{Contact: contact}, func(string) bool {
		return termsOfServiceAgreed
	})
	if err != nil {
		return nil, mapError(err)
	}
	return newAccount(a), nil
}

// Account looks up the account already associated with the client's key,
// mirroring account lookup on an existing Acme::Client.
func (c *Client) Account(ctx context.Context) (*Account, error) {
	a, err := c.ac.GetReg(ctx, "")
	if err != nil {
		return nil, mapError(err)
	}
	return newAccount(a), nil
}

// NewOrder creates a new certificate order for the given DNS identifiers,
// mirroring Acme::Client#new_order(identifiers:).
func (c *Client) NewOrder(ctx context.Context, identifiers []string) (*Order, error) {
	o, err := c.ac.AuthorizeOrder(ctx, xacme.DomainIDs(identifiers...))
	if err != nil {
		return nil, mapError(err)
	}
	return &Order{client: c, o: o}, nil
}
