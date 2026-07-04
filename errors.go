package acme

import (
	"errors"
	"fmt"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Error is the root of the ACME error tree, mirroring Acme::Client::Error.
//
// It wraps an ACME problem document (RFC 8555 §6.7): ProblemType is the problem
// URN (e.g. "urn:ietf:params:acme:error:unauthorized"), Detail is the
// human-readable explanation and StatusCode is the HTTP status the CA returned.
type Error struct {
	// ProblemType is the RFC 8555 problem type URN.
	ProblemType string
	// Detail is the human-readable explanation from the CA.
	Detail string
	// StatusCode is the HTTP status code the CA responded with.
	StatusCode int
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("acme: %d %s", e.StatusCode, e.ProblemType)
	}
	return fmt.Sprintf("acme: %d %s: %s", e.StatusCode, e.ProblemType, e.Detail)
}

// Unauthorized maps urn:ietf:params:acme:error:unauthorized — the client lacks
// authorization to act on a resource. Mirrors Acme::Client::Error::Unauthorized.
type Unauthorized struct{ Problem *Error }

// Error implements the error interface.
func (e *Unauthorized) Error() string { return e.Problem.Error() }

// Unwrap exposes the underlying [*Error] so errors.As(err, new(*Error)) matches.
func (e *Unauthorized) Unwrap() error { return e.Problem }

// Malformed maps urn:ietf:params:acme:error:malformed — the request message was
// malformed. Mirrors Acme::Client::Error::Malformed.
type Malformed struct{ Problem *Error }

// Error implements the error interface.
func (e *Malformed) Error() string { return e.Problem.Error() }

// Unwrap exposes the underlying [*Error].
func (e *Malformed) Unwrap() error { return e.Problem }

// BadNonce maps urn:ietf:params:acme:error:badNonce — the client sent an
// unacceptable anti-replay nonce. Mirrors Acme::Client::Error::BadNonce.
type BadNonce struct{ Problem *Error }

// Error implements the error interface.
func (e *BadNonce) Error() string { return e.Problem.Error() }

// Unwrap exposes the underlying [*Error].
func (e *BadNonce) Unwrap() error { return e.Problem }

// RateLimited maps urn:ietf:params:acme:error:rateLimited — the request exceeds
// a rate limit. RetryAfter carries the parsed Retry-After hint when present.
// Mirrors Acme::Client::Error::RateLimited.
type RateLimited struct {
	Problem *Error
	// RetryAfter is the delay advertised by the CA's Retry-After header, if any.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimited) Error() string { return e.Problem.Error() }

// Unwrap exposes the underlying [*Error].
func (e *RateLimited) Unwrap() error { return e.Problem }

// problemSuffix returns the lower-cased final segment of an ACME problem URN,
// e.g. "unauthorized" for "urn:ietf:params:acme:error:unauthorized".
func problemSuffix(problemType string) string {
	i := strings.LastIndex(problemType, ":")
	if i < 0 {
		return strings.ToLower(problemType)
	}
	return strings.ToLower(problemType[i+1:])
}

// mapError translates an error returned by the underlying x/crypto/acme client
// into the acme-client-flavoured error tree. Non-ACME errors (transport,
// context, decoding) are returned unchanged.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var xe *xacme.Error
	if !errors.As(err, &xe) {
		return err
	}
	base := &Error{
		ProblemType: xe.ProblemType,
		Detail:      xe.Detail,
		StatusCode:  xe.StatusCode,
	}
	switch problemSuffix(xe.ProblemType) {
	case "unauthorized":
		return &Unauthorized{base}
	case "malformed":
		return &Malformed{base}
	case "badnonce":
		return &BadNonce{base}
	case "ratelimited":
		d, _ := xacme.RateLimit(xe)
		return &RateLimited{Problem: base, RetryAfter: d}
	default:
		return base
	}
}
