// Package proxy implements the TLS MITM proxy that intercepts AI API traffic,
// rewrites headers, and forwards requests to the Bifrost gateway.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// GenerateCert creates a TLS certificate for the given domain, signed by the
// organization's CA certificate. Uses ECDSA P-256 for fast key generation and
// small cert sizes.
func GenerateCert(domain string, caCert *x509.Certificate, caTLSCert *tls.Certificate) (*tls.Certificate, error) {
	// Generate a new ECDSA key pair for this domain
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Bifrost Agent"},
		},
		DNSNames:    []string{domain},
		NotBefore:   now.Add(-1 * time.Hour), // small clock skew tolerance
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Get the CA's private key for signing
	caPrivKey := caTLSCert.PrivateKey

	// Sign the certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, caTLSCert.Certificate[0]},
		PrivateKey:  privKey,
	}, nil
}

// GenerateSelfSignedCA creates a new self-signed CA certificate for testing.
// In production, the CA is fetched from the Bifrost management API.
func GenerateSelfSignedCA() (*x509.Certificate, *tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Bifrost Agent CA",
			Organization: []string{"Bifrost"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	return x509Cert, tlsCert, nil
}
