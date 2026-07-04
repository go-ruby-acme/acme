package acme

import (
	"context"
	"encoding/pem"

	xacme "golang.org/x/crypto/acme"
)

// Order is a certificate order, mirroring the Acme::Client order object.
type Order struct {
	client *Client
	o      *xacme.Order
	chain  [][]byte // DER certificate chain, populated by Finalize/Certificate
}

// URL returns the order resource URL.
func (o *Order) URL() string { return o.o.URI }

// Status returns the current order status, e.g. "pending", "ready",
// "processing" or "valid".
func (o *Order) Status() string { return o.o.Status }

// Identifiers returns the DNS identifiers this order covers.
func (o *Order) Identifiers() []string {
	ids := make([]string, len(o.o.Identifiers))
	for i, id := range o.o.Identifiers {
		ids[i] = id.Value
	}
	return ids
}

// Reload re-fetches the order from the CA, refreshing its status and URLs,
// mirroring Order#reload.
func (o *Order) Reload(ctx context.Context) error {
	no, err := o.client.ac.GetOrder(ctx, o.o.URI)
	if err != nil {
		return mapError(err)
	}
	o.o = no
	return nil
}

// Authorizations fetches the authorization objects for the order, mirroring
// Order#authorizations.
func (o *Order) Authorizations(ctx context.Context) ([]*Authorization, error) {
	out := make([]*Authorization, 0, len(o.o.AuthzURLs))
	for _, url := range o.o.AuthzURLs {
		az, err := o.client.ac.GetAuthorization(ctx, url)
		if err != nil {
			return nil, mapError(err)
		}
		out = append(out, &Authorization{client: o.client, a: az})
	}
	return out, nil
}

// Finalize submits the certificate signing request to the CA, waits for the
// order to become valid and downloads the issued chain, mirroring
// Order#finalize(csr:). csr is the DER-encoded PKCS#10 request; use [NewCSR] to
// build one.
func (o *Order) Finalize(ctx context.Context, csr []byte) error {
	der, certURL, err := o.client.ac.CreateOrderCert(ctx, o.o.FinalizeURL, csr, true)
	if err != nil {
		return mapError(err)
	}
	o.chain = der
	o.o.CertURL = certURL
	o.o.Status = xacme.StatusValid
	return nil
}

// Certificate returns the issued certificate chain as a PEM string, mirroring
// Order#certificate. If the chain was already downloaded by [Order.Finalize] it
// is returned directly; otherwise the order is reloaded and the chain fetched
// from the CA.
func (o *Order) Certificate(ctx context.Context) (string, error) {
	if o.chain == nil {
		if err := o.fetchCertificate(ctx); err != nil {
			return "", err
		}
	}
	var buf []byte
	for _, der := range o.chain {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return string(buf), nil
}

func (o *Order) fetchCertificate(ctx context.Context) error {
	if o.o.CertURL == "" {
		if err := o.Reload(ctx); err != nil {
			return err
		}
	}
	if o.o.CertURL == "" {
		return &Error{ProblemType: "urn:go-ruby-acme:error:notReady", Detail: "certificate not ready"}
	}
	der, err := o.client.ac.FetchCert(ctx, o.o.CertURL, true)
	if err != nil {
		return mapError(err)
	}
	o.chain = der
	return nil
}
