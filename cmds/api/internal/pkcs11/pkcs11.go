// Package pkcs11 is a coupled package that interacts with the PKCS#11 interface of a library specified through viper configuration;
// it fetches the key pair and their corresponding certificate which are specified by viper configuration (see the conf.go file in this package);
// it also exposes the *crypto11.Context under use.
package pkcs11

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ThalesGroup/crypto11"
)

var _crypto11Ctx *crypto11.Context

func GetCrypt11Ctx() (*crypto11.Context, error) {
	err := ensureCrypto11Ctx()
	if err != nil {
		return nil, err
	}

	return _crypto11Ctx, nil
}

func ensureCrypto11Ctx() (err error) {
	if _crypto11Ctx != nil {
		return nil
	}

	libPath, err := getLibPathConf()
	if err != nil {
		return err
	}

	slot, serial, label, err := getTokenIdsConf()
	if err != nil {
		return err
	}

	if slot != -1 {
		slog.Info("Using the token slot conf to identify a token.", "slot", slot)
		serial = ""
		label = ""
	} else if serial != "" {
		slog.Info("Using the token serial conf to identify a token.", "serial", serial)
		slot = -1
		label = ""
	} else if label != "" {
		slog.Info("Using the token label conf to identify a token.", "label", label)
		slot = -1
		serial = ""
	} else {
		// Never should reach here when we have a normal behaving user; non-existence of those ids should be reported through the earlier getTokenIdsConf returned error.
		panic("should not reach here")
	}

	noLogin := false
	pin, err := getTokenPinConf()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Try no login.
			noLogin = true
		} else {
			return err
		}
	}

	slotP := &slot
	if slot == -1 {
		slotP = nil
	}

	_crypto11Ctx, err = crypto11.Configure(&crypto11.Config{
		Path:              libPath,
		SlotNumber:        slotP,
		TokenSerial:       serial,
		TokenLabel:        label,
		Pin:               pin,
		LoginNotSupported: noLogin,

		// TODO: why open concurrent sessions? Just open a session with support for concurrency (or else concurrent sessions would not help anyway? Or would they?)?
		MaxSessions: 0,

		// TODO: pick a good timeout value and properly handle ErrTimeOut (from package github.com/thales-e-security/pool) to respond with HTTP 503 status code.
		PoolWaitTimeout: 7 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("crypto11 context init failed; %w", err)
	}

	return nil
}

func GetKert(kertId []byte, kertLabel string) (pvKey crypto.PrivateKey, pubKey crypto.PublicKey, cert *x509.Certificate, err error) {
	crypto11Ctx, err := GetCrypt11Ctx()
	if err != nil {
		return
	}

	pvKey, err = crypto11Ctx.FindKeyPair(kertId, []byte(kertLabel))
	if err != nil {
		err = fmt.Errorf("finding the key pair failed; %w", err)
		return
	}
	if pvKey == nil {
		err = fmt.Errorf("no such key pair found")
		return
	}

	cert, err = crypto11Ctx.FindCertificate(kertId, []byte(kertLabel), nil)
	if err != nil {
		err = fmt.Errorf("finding the certificate failed; %w", err)
		return
	}
	if cert == nil {
		err = fmt.Errorf("no such certificate found")
		return
	}

	pubKey = pvKey.(interface {
		Public() crypto.PublicKey
	}).Public()
	if pubKey == nil {
		pubKey = cert.PublicKey
	}

	return
}

func GetKertByConf() (pvKey crypto.PrivateKey, pubKey crypto.PublicKey, cert *x509.Certificate, err error) {
	crypto11Ctx, err := GetCrypt11Ctx()
	if err != nil {
		return
	}

	findAll := false
	kertId, kertLabel, err := getKertIdsConf()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return
		} else {
			// Try finding all kerts and picking up one.
			findAll = true
		}
	}

	if findAll {
		slog.Warn("No way to identify a kert is provided; fetching all kerts from the token.")

		var kerts []tls.Certificate
		kerts, err = crypto11Ctx.FindAllPairedCertificates()
		if err != nil {
			err = fmt.Errorf("fetching all kerts failed; %w", err)
			return
		}

		if len(kerts) == 0 {
			err = fmt.Errorf("no kert present in the token")
			return
		} else if len(kerts) > 1 {
			slog.Warn("The token contains many kerts; picking the first one fetched.", "kertsCount", len(kerts))
		}

		kert := kerts[0]

		pvKey = kert.PrivateKey
		cert = kert.Leaf
		pubKey = cert.PublicKey
	} else {
		return GetKert(kertId, kertLabel)
	}

	return
}
