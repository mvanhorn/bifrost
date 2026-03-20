package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/maximhq/bifrost/agent/config"
)

func TestGenerateSelfSignedCA(t *testing.T) {
	caCert, caTLSCert, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	if !caCert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if caCert.Subject.CommonName != "Bifrost Agent CA" {
		t.Errorf("unexpected CN: %s", caCert.Subject.CommonName)
	}
	if caTLSCert.PrivateKey == nil {
		t.Error("CA private key should not be nil")
	}
}

func TestGenerateCert(t *testing.T) {
	caCert, caTLSCert, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}

	domain := "api.openai.com"
	cert, err := GenerateCert(domain, caCert, caTLSCert)
	if err != nil {
		t.Fatal(err)
	}

	if len(cert.Certificate) != 2 {
		t.Errorf("expected 2 certs in chain (leaf + CA), got %d", len(cert.Certificate))
	}

	// Parse the leaf cert and verify it
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != domain {
		t.Errorf("leaf CN = %s, want %s", leaf.Subject.CommonName, domain)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
		t.Errorf("leaf DNSNames = %v, want [%s]", leaf.DNSNames, domain)
	}

	// Verify the leaf is signed by the CA
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("leaf cert verification failed: %v", err)
	}
}

func TestCertStore_GetOrCreate(t *testing.T) {
	caCert, caTLSCert, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	store := NewCertStore(caCert, caTLSCert)

	// First call should generate
	cert1, err := store.GetOrCreate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}

	// Second call should return cached
	cert2, err := store.GetOrCreate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}

	// Should be the same pointer (cached)
	if cert1 != cert2 {
		t.Error("expected cached cert to be returned")
	}

	// Different domain should be different cert
	cert3, err := store.GetOrCreate("api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert1 == cert3 {
		t.Error("expected different cert for different domain")
	}
}

func TestCertStore_TLSHandshake(t *testing.T) {
	caCert, caTLSCert, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	store := NewCertStore(caCert, caTLSCert)

	cert, err := store.GetOrCreate("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}

	// Verify the cert can be used in a TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Error("TLS config should have 1 certificate")
	}
}

func TestRewriteRequest(t *testing.T) {
	rule := &config.DomainRule{
		Hostname:          "api.openai.com",
		IntegrationPrefix: "/openai",
		PreservePath:      true,
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer sk-test-key")
	req.Header.Set("Content-Type", "application/json")

	err = RewriteRequest(req, rule, "https://gateway.example.com", "vk-test-123")
	if err != nil {
		t.Fatal(err)
	}

	// Verify URL rewriting
	if req.URL.Scheme != "https" {
		t.Errorf("scheme = %s, want https", req.URL.Scheme)
	}
	if req.URL.Host != "gateway.example.com" {
		t.Errorf("host = %s, want gateway.example.com", req.URL.Host)
	}
	if req.URL.Path != "/openai/v1/chat/completions" {
		t.Errorf("path = %s, want /openai/v1/chat/completions", req.URL.Path)
	}

	// Verify headers
	if req.Host != "gateway.example.com" {
		t.Errorf("Host header = %s, want gateway.example.com", req.Host)
	}
	if req.Header.Get("x-bf-vk") != "vk-test-123" {
		t.Errorf("x-bf-vk = %s, want vk-test-123", req.Header.Get("x-bf-vk"))
	}
	if req.Header.Get("X-Forwarded-Host") != "api.openai.com" {
		t.Errorf("X-Forwarded-Host = %s, want api.openai.com", req.Header.Get("X-Forwarded-Host"))
	}
	if req.Header.Get("X-Bifrost-Agent") != "bifrost-agent/0.1.0" {
		t.Errorf("X-Bifrost-Agent = %s, want bifrost-agent/0.1.0", req.Header.Get("X-Bifrost-Agent"))
	}

	// Original headers should be preserved
	if req.Header.Get("Authorization") != "Bearer sk-test-key" {
		t.Errorf("Authorization header was modified: %s", req.Header.Get("Authorization"))
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type header was modified: %s", req.Header.Get("Content-Type"))
	}
}

func TestRewriteRequest_AnthropicDomain(t *testing.T) {
	rule := &config.DomainRule{
		Hostname:          "api.anthropic.com",
		IntegrationPrefix: "/anthropic",
		PreservePath:      true,
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", "sk-ant-test")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "messages-2024-12-19")

	err = RewriteRequest(req, rule, "https://gateway.example.com", "vk-test-456")
	if err != nil {
		t.Fatal(err)
	}

	if req.URL.Path != "/anthropic/v1/messages" {
		t.Errorf("path = %s, want /anthropic/v1/messages", req.URL.Path)
	}

	// Anthropic-specific headers must be preserved
	if req.Header.Get("x-api-key") != "sk-ant-test" {
		t.Errorf("x-api-key was modified")
	}
	if req.Header.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("anthropic-version was modified")
	}
	if req.Header.Get("anthropic-beta") != "messages-2024-12-19" {
		t.Errorf("anthropic-beta was modified")
	}
}
