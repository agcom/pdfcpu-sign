package testutils

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

var rnd = mathrand.New(mathrand.NewSource(time.Now().UnixMilli()))

func GenRsaKeyPair() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rnd, 2048)
	if err != nil {
		panic(fmt.Errorf("failed to generate an RSA private key from a pseudo-random source; %w", err))
	}
	return key
}

func GenKeyPair() (crypto.PrivateKey, crypto.PublicKey) {
	rsaKey := GenRsaKeyPair()
	return rsaKey, &rsaKey.PublicKey
}

func GenCaCert(pvKey crypto.PrivateKey, pubKey crypto.PublicKey) *x509.Certificate {
	// Use a random serial to not clash with other test environments' test certificates (little chance anyway).
	rndSerial, _ := cryptorand.Int(rnd, new(big.Int).SetBit(new(big.Int), 128, 1))
	certTemplate := x509.Certificate{
		SerialNumber:          rndSerial,
		Subject:               pkix.Name{Organization: []string{"Test"}},
		Issuer:                pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * 24 * time.Hour), // Valid for 2 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true, // Fake to be a CA certificate
		MaxPathLenZero:        true,
	}
	certDer, err := x509.CreateCertificate(rnd, &certTemplate, &certTemplate, pubKey, pvKey)
	if err != nil {
		panic(fmt.Errorf("failed to generate a fake CA certificate; %w", err))
	}

	certs, err := x509.ParseCertificates(certDer)
	if err != nil {
		panic(fmt.Errorf("failed to parse a just generated certificate DER; %w", err))
	}
	cert := certs[0]

	return cert
}

func GenKert() (pvKey crypto.PrivateKey, pubKey crypto.PublicKey, cert *x509.Certificate) {
	pvKey, pubKey = GenKeyPair()
	cert = GenCaCert(pvKey, pubKey)
	return
}

func KertToPfx(pvKey crypto.PrivateKey, cert *x509.Certificate, pass string) ([]byte, error) {
	pfx, err := pkcs12.Modern.Encode(pvKey, cert, []*x509.Certificate{cert}, pass)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#12; %w", err)
	}

	return pfx, nil
}
