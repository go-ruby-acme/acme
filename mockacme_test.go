package acme_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockACME is an in-process, in-memory ACME (RFC 8555) server sufficient to
// drive the full acme-client flow — directory, new-nonce, new-account,
// new-order, authz, challenge, finalize and cert download — with no real
// network. Individual endpoints can be told to fail to exercise error paths.
type mockACME struct {
	srv     *httptest.Server
	nonce   atomic.Int64
	certPEM []byte

	// error-injection toggles
	failAccount   int    // if non-zero, new-account replies with this status + problem
	accountProb   string // full problem type URN for failAccount
	badNonceOnce  atomic.Bool
	failChallenge bool // challenge validates to "invalid" with an error
	rateLimitAcct bool // new-account replies 429 rateLimited (with Retry-After)

	// state controlling the order/authz/challenge status machine
	challengeStatus  string // status returned by challenge + authz + order gates
	orderNoCertURL   bool   // finalize/order omit the certificate URL
	failNewOrder     bool   // new-order replies malformed
	failAuthz        bool   // authz fetch replies malformed
	failChallengeReq bool   // challenge POST (accept/get) replies malformed
	failFinalize     bool   // finalize replies malformed
	failCert         bool   // cert download replies malformed
	failOrderGet     bool   // GET order replies malformed
	onlyHTTP01       bool   // authz offers only the http-01 challenge
}

func newMockACME(t *testing.T) *mockACME {
	t.Helper()
	m := &mockACME{challengeStatus: "valid"}
	m.certPEM = selfSignedChainPEM(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/new-nonce", m.handleNewNonce)
	mux.HandleFunc("/new-account", m.handleNewAccount)
	mux.HandleFunc("/account/1", m.handleAccount)
	mux.HandleFunc("/new-order", m.handleNewOrder)
	mux.HandleFunc("/order/1", m.handleOrder)
	mux.HandleFunc("/order/1/finalize", m.handleFinalize)
	mux.HandleFunc("/authz/1", m.handleAuthz)
	mux.HandleFunc("/challenge/1", m.handleChallenge)
	mux.HandleFunc("/cert/1", m.handleCert)
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockACME) url(path string) string { return m.srv.URL + path }

// setNonce writes a fresh anti-replay nonce on every response, as RFC 8555
// requires. When badNonceOnce is armed it emits a sentinel the client rejects.
func (m *mockACME) setNonce(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", m.nonce.Add(1)))
}

func (m *mockACME) writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	m.setNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   problemType,
		"detail": detail,
	})
}

const urnPrefix = "urn:ietf:params:acme:error:"

func (m *mockACME) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	m.setNonce(w)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"newNonce":   m.url("/new-nonce"),
		"newAccount": m.url("/new-account"),
		"newOrder":   m.url("/new-order"),
		"revokeCert": m.url("/revoke-cert"),
		"keyChange":  m.url("/key-change"),
		"meta":       map[string]any{"termsOfService": m.url("/terms")},
	})
}

func (m *mockACME) handleNewNonce(w http.ResponseWriter, _ *http.Request) {
	m.setNonce(w)
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockACME) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	// A badNonce reply is armed once to exercise the transport's retry.
	if m.badNonceOnce.CompareAndSwap(true, false) {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"badNonce", "bad nonce")
		return
	}
	if m.rateLimitAcct {
		w.Header().Set("Retry-After", "5")
		m.writeProblem(w, http.StatusTooManyRequests, urnPrefix+"rateLimited", "slow down")
		return
	}
	if m.failAccount != 0 {
		m.writeProblem(w, m.failAccount, m.accountProb, "account rejected")
		return
	}
	// RFC 8555: a registration returns 201 Created, while an existing-account
	// lookup (onlyReturnExisting) returns 200 OK. The transport treats a 201 on
	// a lookup as retriable, so the two must be distinguished by the JWS payload.
	status := http.StatusCreated
	if jwsPayloadContains(r, "onlyReturnExisting") {
		status = http.StatusOK
	}
	m.setNonce(w)
	w.Header().Set("Location", m.url("/account/1"))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "valid",
		"contact": []string{"mailto:admin@example.com"},
	})
}

// jwsPayloadContains decodes the JWS request body and reports whether its
// (base64url) payload contains the given substring.
func jwsPayloadContains(r *http.Request, sub string) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(body, &jws) != nil || jws.Payload == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), sub)
}

func (m *mockACME) handleAccount(w http.ResponseWriter, _ *http.Request) {
	m.setNonce(w)
	w.Header().Set("Location", m.url("/account/1"))
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "valid",
		"contact": []string{"mailto:admin@example.com"},
	})
}

func (m *mockACME) handleNewOrder(w http.ResponseWriter, _ *http.Request) {
	if m.failNewOrder {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "bad order request")
		return
	}
	m.setNonce(w)
	w.Header().Set("Location", m.url("/order/1"))
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(m.orderBody("pending"))
}

func (m *mockACME) orderBody(status string) map[string]any {
	body := map[string]any{
		"status":         status,
		"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
		"authorizations": []string{m.url("/authz/1")},
		"finalize":       m.url("/order/1/finalize"),
	}
	if status == "valid" && !m.orderNoCertURL {
		body["certificate"] = m.url("/cert/1")
	}
	return body
}

func (m *mockACME) handleOrder(w http.ResponseWriter, _ *http.Request) {
	if m.failOrderGet {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "bad order")
		return
	}
	m.setNonce(w)
	_ = json.NewEncoder(w).Encode(m.orderBody(m.challengeStatus))
}

func (m *mockACME) handleFinalize(w http.ResponseWriter, _ *http.Request) {
	if m.failFinalize {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "bad csr")
		return
	}
	m.setNonce(w)
	_ = json.NewEncoder(w).Encode(m.orderBody("valid"))
}

func (m *mockACME) handleAuthz(w http.ResponseWriter, _ *http.Request) {
	if m.failAuthz {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "bad authz")
		return
	}
	m.setNonce(w)
	challenges := []map[string]any{
		{"type": "http-01", "url": m.url("/challenge/1"), "token": "tok-http", "status": "pending"},
	}
	if !m.onlyHTTP01 {
		challenges = append(challenges,
			map[string]any{"type": "dns-01", "url": m.url("/challenge/1"), "token": "tok-dns", "status": "pending"},
			map[string]any{"type": "tls-alpn-01", "url": m.url("/challenge/1"), "token": "tok-alpn", "status": "pending"},
		)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     m.challengeStatus,
		"identifier": map[string]string{"type": "dns", "value": "example.com"},
		"challenges": challenges,
	})
}

func (m *mockACME) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	if m.failChallengeReq {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "bad challenge")
		return
	}
	m.setNonce(w)
	ch := map[string]any{
		"type":   "http-01",
		"url":    m.url("/challenge/1"),
		"token":  "tok-http",
		"status": m.challengeStatus,
	}
	if m.failChallenge {
		ch["status"] = "invalid"
		ch["error"] = map[string]any{
			"type":   "urn:ietf:params:acme:error:unauthorized",
			"detail": "invalid response",
		}
	}
	_ = json.NewEncoder(w).Encode(ch)
}

func (m *mockACME) handleCert(w http.ResponseWriter, _ *http.Request) {
	if m.failCert {
		m.writeProblem(w, http.StatusBadRequest, urnPrefix+"malformed", "no cert")
		return
	}
	m.setNonce(w)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(m.certPEM)
}

// selfSignedChainPEM produces a two-certificate PEM chain (leaf + issuer) so the
// bundle path of the cert download is exercised.
func selfSignedChainPEM(t *testing.T) []byte {
	t.Helper()
	var out []byte
	for i, cn := range []string{"example.com", "Mock ACME CA"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         i == 1,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
