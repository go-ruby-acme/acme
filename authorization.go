package acme

import (
	xacme "golang.org/x/crypto/acme"
)

// ACME challenge type identifiers.
const (
	ChallengeHTTP01    = "http-01"
	ChallengeDNS01     = "dns-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)

// Authorization is an authorization for a single identifier, mirroring the
// Acme::Client authorization object.
type Authorization struct {
	client *Client
	a      *xacme.Authorization
}

// URL returns the authorization resource URL.
func (a *Authorization) URL() string { return a.a.URI }

// Status returns the authorization status, e.g. "pending" or "valid".
func (a *Authorization) Status() string { return a.a.Status }

// Domain returns the identifier value this authorization is for.
func (a *Authorization) Domain() string { return a.a.Identifier.Value }

// Wildcard reports whether the authorization is for a wildcard identifier.
func (a *Authorization) Wildcard() bool { return a.a.Wildcard }

// Challenges returns every challenge offered for the authorization, mirroring
// Authorization#challenges.
func (a *Authorization) Challenges() []*Challenge {
	out := make([]*Challenge, len(a.a.Challenges))
	for i, ch := range a.a.Challenges {
		out[i] = &Challenge{client: a.client, c: ch}
	}
	return out
}

// challengeByType returns the offered challenge of the given type, or nil.
func (a *Authorization) challengeByType(typ string) *Challenge {
	for _, ch := range a.a.Challenges {
		if ch.Type == typ {
			return &Challenge{client: a.client, c: ch}
		}
	}
	return nil
}

// HTTP01 returns the http-01 challenge, or nil if the CA did not offer one.
// Mirrors Authorization#http01.
func (a *Authorization) HTTP01() *Challenge { return a.challengeByType(ChallengeHTTP01) }

// DNS01 returns the dns-01 challenge, or nil if the CA did not offer one.
// Mirrors Authorization#dns01.
func (a *Authorization) DNS01() *Challenge { return a.challengeByType(ChallengeDNS01) }

// TLSALPN01 returns the tls-alpn-01 challenge, or nil if the CA did not offer
// one. Mirrors Authorization#tls_alpn01.
func (a *Authorization) TLSALPN01() *Challenge { return a.challengeByType(ChallengeTLSALPN01) }
