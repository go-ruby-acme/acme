package acme

import xacme "golang.org/x/crypto/acme"

// NewChallengeForTest builds a bare Challenge bound to a client for white-box
// testing of key-authorization derivation. Test-only; not part of the API.
func NewChallengeForTest(c *Client, token string) *Challenge {
	return &Challenge{client: c, c: &xacme.Challenge{Token: token}}
}
