package signpdf

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/pkcs11"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/testutils"
	"log"
	"log/slog"
	"os"
	"testing"
)

var pvKey crypto.PrivateKey
var pubKey crypto.PublicKey
var cert *x509.Certificate
var certChains [][]*x509.Certificate

var tmpDir string

func TestMain(m *testing.M) {
	var err error
	tmpDir, err = os.MkdirTemp("", "agcom-pdfcpu-sign-internal-signpdf-tests-*")
	if err != nil {
		panic(fmt.Errorf("failed to create a temporary directory; %w", err))
	}

	os.Exit(mainDeferSafe(m))
}

// mainDeferSafe would not call os.Exit and therefore gives time to the cleanup defer functions to behave.
func mainDeferSafe(m *testing.M) int {
	crypto11Ctx, err := pkcs11.GetCrypt11Ctx()
	if err != nil {
		log.Panicf("Getting crypto11 context failed; %v.\n", err)
	}

	defer func() {
		err := crypto11Ctx.Close()
		if err != nil {
			slog.Error("Closing the crypto11 context failed.", "error", err)
		}
	}()

	kertId, err := testutils.AddTestKert(crypto11Ctx)
	if err != nil {
		log.Panicf("Adding a test kert failed; %v.\n", err)
	}

	defer func() {
		err := crypto11Ctx.DeleteCertificate(kertId, nil, nil)
		if err != nil {
			slog.Error(
				"Deleting the test certificate failed.",
				"certIdBase64", base64.StdEncoding.EncodeToString(kertId),
			)
		}

		key, err := crypto11Ctx.FindKeyPair(kertId, nil)
		if err != nil {
			slog.Error(
				"Deleting the test key pair failed.",
				"keyIdBase64",
				base64.StdEncoding.EncodeToString(kertId),
			)
		}

		testutils.TryDelKeyPair(key, kertId)
	}()

	pvKey, pubKey, cert, err = pkcs11.GetKert(kertId, "")
	if err != nil {
		log.Panicf("Getting the just now create kert failed (kertIdBase64=%s).", base64.StdEncoding.EncodeToString(kertId))
	}
	certChains = [][]*x509.Certificate{{cert}}

	exitCode := m.Run()

	return exitCode
}
