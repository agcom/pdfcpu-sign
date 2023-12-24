package testutils

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"io"
	"log/slog"
	"math/big"
	mathrand "math/rand"
	"time"
)

// We do not need to consume the cryptographical random numbers for testing.
var rnd = mathrand.New(mathrand.NewSource(time.Now().UnixMilli()))

// AddTestKert generates a test key pair and a corresponding test CA certificate.
func AddTestKert(crypto11Ctx *crypto11.Context) ([]byte, error) {
	keyId, err := AddTestKeyPair(crypto11Ctx)
	if err != nil {
		return nil, fmt.Errorf("adding test key pair failed; %w", err)
	}

	key, err := crypto11Ctx.FindKeyPair(keyId, nil)
	if err != nil {
		TryDelKeyPair(key, keyId)
		return nil, fmt.Errorf("unable to retrieve just now created key pair; %w", err)
	}

	err = AddTestCaCertWithKey(crypto11Ctx, keyId, key)
	if err != nil {
		TryDelKeyPair(key, keyId)
		return nil, fmt.Errorf("adding test CA certificate failed; %w", err)
	}

	return keyId, nil
}

func AddTestKeyPair(crypto11Ctx *crypto11.Context) ([]byte, error) {
	keyId := make([]byte, 7)
	_, _ = io.ReadFull(rnd, keyId) // Would not error as long as using pseudo random number generator.

	// TODO: generate the key using the rsa package and then import it into the token.
	_, err := crypto11Ctx.GenerateRSAKeyPair(keyId, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating and adding RSA key failed; %w", err)
	}

	return keyId, nil
}

func AddTestCaCertWithKey(crypto11Ctx *crypto11.Context, keyId []byte, key crypto.Signer) error {
	// Use a random serial to not clash with other test environments' test certificates (little chance anyway).
	rndSerial, _ := rand.Int(rnd, new(big.Int).SetBit(new(big.Int), 128, 1))
	certTemplate := x509.Certificate{
		SerialNumber:          rndSerial,
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * 24 * time.Hour), // Valid for 2 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true, // Fake to be a CA certificate
		MaxPathLenZero:        true,
	}
	certDer, err := x509.CreateCertificate(rnd, &certTemplate, &certTemplate, key.Public(), key)
	if err != nil {
		return fmt.Errorf("creating certificate failed; %w", err)
	}

	certs, err := x509.ParseCertificates(certDer)
	if err != nil {
		return fmt.Errorf("parsing generated DER certificate failed; %w", err)
	}
	cert := certs[0]

	// Put the certificate inside the token.
	err = crypto11Ctx.ImportCertificate(keyId, cert)
	if err != nil {
		return fmt.Errorf("importing certificate into token failed; %w", err)
	}

	return nil
}

func TryDelKeyPair(key crypto11.Signer, keyId []byte) {
	err := key.Delete()
	if err != nil {
		slog.Error("Deleting a test key pair failed.", "keyIdBase64", base64.StdEncoding.EncodeToString(keyId))
	}
}

func TryPurgeAllKerts(crypto11Ctx *crypto11.Context) {
	kerts, err := crypto11Ctx.FindAllPairedCertificates()
	if err != nil {
		slog.Error("Purging all kerts failed.", "error", err)
		return
	}

	for _, kert := range kerts {
		err = crypto11Ctx.DeleteCertificate(nil, nil, kert.Leaf.SerialNumber)
		if err != nil {
			slog.Error("Deleting a certificate failed.", "serial", kert.Leaf.SerialNumber, "error", err)
		}

		err = kert.PrivateKey.(crypto11.Signer).Delete()
		if err != nil {
			slog.Error("Deleting a key pair failed.", "error", err)
		}
	}
}
