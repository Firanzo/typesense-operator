package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

func makeSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writePEM(bType string, payload []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := pem.Encode(buf, &pem.Block{Type: bType, Bytes: payload})
	return buf.Bytes(), err
}

// GenerateWebhookCerts generates a self-signed CA and a server certificate for the webhook.
func GenerateWebhookCerts(serviceName, namespace string) ([]byte, []byte, []byte, error) {
	start := time.Now()
	end := start.Add(365 * 24 * time.Hour)

	caSer, err := makeSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	rootCA := &x509.Certificate{
		SerialNumber: caSer,
		Subject: pkix.Name{
			Organization: []string{"typesense-operator"},
			CommonName:   "typesense-operator-ca",
		},
		NotBefore:             start,
		NotAfter:              end,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM, err := writePEM("CERTIFICATE", rootBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	leafSer, err := makeSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	leaf := &x509.Certificate{
		SerialNumber: leafSer,
		Subject: pkix.Name{
			Organization: []string{"typesense-operator"},
			CommonName:   serviceName,
		},
		DNSNames: []string{
			serviceName,
			serviceName + "." + namespace,
			serviceName + "." + namespace + ".svc",
		},
		NotBefore:   start,
		NotAfter:    end,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, leaf, rootCA, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM, err := writePEM("CERTIFICATE", leafBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, err
	}

	keyPEM, err := writePEM("PRIVATE KEY", keyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return caPEM, certPEM, keyPEM, nil
}
