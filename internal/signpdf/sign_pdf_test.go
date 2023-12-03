package signpdf

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/ThalesIgnite/crypto11"
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"github.com/agcom/pdfcpu-sign/internal/testutil"
	pdfsign "github.com/digitorus/pdfsign/sign"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/stretchr/testify/require"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"
)

var pdfSigner *PdfSigner

func TestMain(m *testing.M) {
	os.Exit(MainDeferSafe(m))
}

// MainDeferSafe would not call os.Exit and therefore gives the cleanup defer functions to behave.
func MainDeferSafe(m *testing.M) int {
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

	key := kert.PrivateKey.(crypto11.Signer) // Returned private keys from crypto11 do implement crypto11.Signer (the purpose of the library).
	cert := kert.Leaf

	TestCertRoots = x509.NewCertPool()
	TestCertRoots.AddCert(cert)

	pdfSigner = NewPdfSigner(key, cert)

	exitCode := m.Run()

	return exitCode
}

func TestPDFSigner_Sign(t *testing.T) {
	err := pdfSigner.Sign("./sample.pdf", "./sample-signed.pdf", &pdfsign.SignDataSignature{
		CertType:   pdfsign.CertificationSignature,
		DocMDPPerm: pdfsign.DoNotAllowAnyChangesPerms,
		Info: pdfsign.SignDataSignatureInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Sealing",
			ContactInfo: "example@example.com",
			Date:        time.Now(),
		},
	})

	require.NoError(t, err)

	// Validate the output PDF file
	err = pdfcpu.ValidateFile("./sample-signed.pdf", nil)

	require.NoError(t, err)
}
