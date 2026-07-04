package acme

import (
	"context"

	xacme "golang.org/x/crypto/acme"
)

// Challenge is a single ACME challenge, mirroring the Acme::Client challenge
// object.
type Challenge struct {
	client *Client
	c      *xacme.Challenge
}

// Type returns the challenge type, e.g. "http-01".
func (ch *Challenge) Type() string { return ch.c.Type }

// Token returns the challenge token.
func (ch *Challenge) Token() string { return ch.c.Token }

// URL returns the challenge resource URL.
func (ch *Challenge) URL() string { return ch.c.URI }

// Status returns the challenge status, e.g. "pending" or "valid", mirroring
// Challenge#status.
func (ch *Challenge) Status() string { return ch.c.Status }

// Error returns the reason the challenge failed, or nil, mirroring
// Challenge#error. The value is mapped onto the acme error tree.
func (ch *Challenge) Error() error { return mapError(ch.c.Error) }

// KeyAuthorization returns the key authorization ("token.thumbprint") to be
// served for the challenge, mirroring Challenge#key_authorization.
func (ch *Challenge) KeyAuthorization() (string, error) {
	ka, err := ch.client.ac.HTTP01ChallengeResponse(ch.c.Token)
	if err != nil {
		return "", mapError(err)
	}
	return ka, nil
}

// RequestValidation tells the CA the client is ready to answer the challenge,
// mirroring Challenge#request_validation. The challenge's status is refreshed
// from the CA's response.
func (ch *Challenge) RequestValidation(ctx context.Context) error {
	nc, err := ch.client.ac.Accept(ctx, ch.c)
	if err != nil {
		return mapError(err)
	}
	ch.c = nc
	return nil
}

// Reload re-fetches the challenge from the CA, refreshing its status and error,
// mirroring Challenge#reload.
func (ch *Challenge) Reload(ctx context.Context) error {
	nc, err := ch.client.ac.GetChallenge(ctx, ch.c.URI)
	if err != nil {
		return mapError(err)
	}
	ch.c = nc
	return nil
}
