package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
)

// NewCSR builds a DER-encoded PKCS#10 certificate signing request for the given
// key and DNS names, suitable for [Order.Finalize]. The first name becomes the
// subject common name and every name is included as a DNS SAN, mirroring the
// CSR that Acme::Client::CertificateRequest produces.
func NewCSR(key crypto.Signer, names ...string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{DNSNames: names}
	if len(names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}
