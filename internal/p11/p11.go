package p11

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"time"
)

var C11Ctx *crypto11.Context

func InitCrypto11Ctx() error {
	var err error
	C11Ctx, err = crypto11.Configure(&crypto11.Config{
		Path:            Pkcs11LibPath,
		SlotNumber:      &TokenSlot,
		TokenSerial:     TokenSerial,
		TokenLabel:      TokenLabel,
		Pin:             TokenPin,
		MaxSessions:     0,               // TODO: why open concurrent sessions? Just open a session with support for concurrency (or else concurrent sessions would not help anyway?)!
		PoolWaitTimeout: 7 * time.Second, // TODO: pick a good timeout value and properly handle ErrTimeOut (from package github.com/thales-e-security/pool) to respond with HTTP 503 status code.
	})
	if err != nil {
		return fmt.Errorf("crypto11 context initialization failed; %w", err)
	}
	// TODO: C11Ctx.Close() on graceful shutdown (on application context done).

	return nil
}

var Key crypto.Signer
var Cert *x509.Certificate

func InitKert() error {
	// TODO: find the private key, the public key, and the public key certificate by explicitly identifying it via configurations; doing so removes the security concern of un-deterministic behavior on HSM changes.
	kerts, err := C11Ctx.FindAllPairedCertificates()
	if err != nil {
		return fmt.Errorf("fetching keys/certs failed; %w", err)
	} else if len(kerts) == 0 {
		return errors.New("no key/cert present in the token")
	} else if len(kerts) > 1 {
		// Fail on purpose instead of for example picking the first one by default.
		return fmt.Errorf("too many keys/certs inside the token (%d keys/certs) and picking one is not implemented", len(kerts))
	}

	kert := kerts[0]

	Key = kert.PrivateKey.(crypto.Signer) // Returned private keys from crypto11 do implement crypto.Signer (the purpose of the library).
	Cert = kert.Leaf
	if err != nil {
		return fmt.Errorf("failed to build the certificate's chains of trust (possible untrusted public key); %w", err)
	}

	return nil
}
