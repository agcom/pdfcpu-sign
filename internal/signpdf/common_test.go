package signpdf

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"github.com/agcom/pdfcpu-sign/internal/model"
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"github.com/agcom/pdfcpu-sign/internal/testutil"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"
)

var pvKey crypto.PrivateKey
var cert *x509.Certificate
var certChains [][]*x509.Certificate

func TestMain(m *testing.M) {
	os.Exit(mainDeferSafe(m))
}

// mainDeferSafe would not call os.Exit and therefore gives time to the cleanup defer functions to behave.
func mainDeferSafe(m *testing.M) int {
	err := p11.InitCrypto11Ctx()
	if err != nil {
		log.Panicf("Creating crypto11 context failed; %v.\n", err)
	}

	c11Ctx := p11.C11Ctx

	defer func() {
		err := c11Ctx.Close()
		if err != nil {
			slog.Error("Closing crypto11 context failed.", "error", err)
		}
	}()

	keyId, err := testutil.AddTestKert(c11Ctx)
	if err != nil {
		log.Panicf("Generating a test kert (key pair + certificate) failed; %v.\n", err)
	}

	defer func() {
		err := c11Ctx.DeleteCertificate(keyId, nil, nil)
		if err != nil {
			slog.Error(
				"Deleting a test certificate failed.",
				"keyIdBase64", base64.StdEncoding.EncodeToString(keyId),
			)
		}

		key, err := c11Ctx.FindKeyPair(keyId, nil)
		if err != nil {
			slog.Error("Deleting a test key pair failed.", "keyIdBase64", base64.StdEncoding.EncodeToString(keyId))
		}

		testutil.TryDelKeyPair(key, keyId)
	}()

	kerts, err := c11Ctx.FindAllPairedCertificates()
	if err != nil {
		log.Panicf("Finding the just now created kert failed; %v.\n", err)
	}

	if len(kerts) > 1 {
		log.Panicf("Too many kerts (%d).\n", len(kerts))
	}

	kert := kerts[0]

	pvKey = kert.PrivateKey
	cert = kert.Leaf
	certChains = [][]*x509.Certificate{{cert}}

	TestCertRoots = x509.NewCertPool()
	TestCertRoots.AddCert(cert)

	exitCode := m.Run()

	return exitCode
}

func newTestCertSignInfo() *model.SignInfo {
	return &model.SignInfo{
		Type:   model.SignTypeCertification,
		DocMdp: model.DocMdpNoChanges,
		SignerInfo: model.SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Test",
			ContactInfo: "example@exmaple.com",
			Date:        time.Now(),
		},
	}
}

func newTestApprovalSignInfo() *model.SignInfo {
	return &model.SignInfo{
		Type: model.SignTypeApproval,
		SignerInfo: model.SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Test",
			ContactInfo: "example@exmaple.com",
			Date:        time.Now(),
		},
	}
}
