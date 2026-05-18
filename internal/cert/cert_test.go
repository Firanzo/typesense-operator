package cert

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateWebhookCerts(t *testing.T) {
	serviceName := "typesense-webhook-service"
	namespace := "typesense-system"

	caPEM, certPEM, keyPEM, err := GenerateWebhookCerts(serviceName, namespace)
	if err != nil {
		t.Fatalf("GenerateWebhookCerts returned an error: %v", err)
	}

	if len(caPEM) == 0 || len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("GenerateWebhookCerts returned empty PEM blocks")
	}

	// Verify that the generated server certificate is valid PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatal("Failed to decode CERTIFICATE PEM block")
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse x509 certificate: %v", err)
	}

	// Verify the correct DNS names are injected
	expectedDNSNames := []string{
		serviceName,
		serviceName + "." + namespace,
		serviceName + "." + namespace + ".svc",
	}

	if len(parsedCert.DNSNames) != len(expectedDNSNames) {
		t.Fatalf("Expected %d DNS names, got %d", len(expectedDNSNames), len(parsedCert.DNSNames))
	}

	// Verify the expiration date is set correctly (approx. 1 year from now)
	timeRemaining := time.Until(parsedCert.NotAfter)
	if timeRemaining < 364*24*time.Hour || timeRemaining > 366*24*time.Hour {
		t.Fatalf("Expected certificate validity to be approx 1 year, got %v", timeRemaining)
	}
}
