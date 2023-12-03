package http

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/agcom/pdfcpu-sign/internal/model"
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"github.com/agcom/pdfcpu-sign/internal/signpdf"
	"github.com/agcom/pdfcpu-sign/internal/testutil"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(MainDeferSafe(m))
}

// MainDeferSafe would not call os.Exit and therefore gives the cleanup defer functions to behave.
func MainDeferSafe(m *testing.M) int {
	err := p11.InitCrypto11Ctx()
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		err := p11.C11Ctx.Close()
		if err != nil {
			slog.Error("Closing crypto11 context failed.", "error", err)
		}
	}()

	keyId, err := testutil.AddTestKert(p11.C11Ctx)
	if err != nil {
		log.Panicf("Generating a test kert (key pair + certificate) failed; %v.\n", err)
	}

	defer func() {
		err := p11.C11Ctx.DeleteCertificate(keyId, nil, nil)
		if err != nil {
			slog.Error(
				"Deleting a test certificate failed.",
				"keyIdBase64", base64.StdEncoding.EncodeToString(keyId),
			)
		}

		key, err := p11.C11Ctx.FindKeyPair(keyId, nil)
		if err != nil {
			slog.Error("Deleting a test key pair failed.", "keyIdBase64", base64.StdEncoding.EncodeToString(keyId))
		}

		err = key.Delete()
		if err != nil {
			slog.Error("Deleting a test key pair failed.", "keyIdBase64", base64.StdEncoding.EncodeToString(keyId))
		}
	}()

	kerts, err := p11.C11Ctx.FindAllPairedCertificates()
	if err != nil {
		log.Panicf("Finding the just now created kert failed; %v.\n", err)
	}

	if len(kerts) > 1 {
		log.Panicf("Too many kerts (%d).\n", len(kerts))
	}

	kert := kerts[0]
	cert := kert.Leaf

	signpdf.TestCertRoots = x509.NewCertPool()
	signpdf.TestCertRoots.AddCert(cert)

	err = p11.InitKert()
	if err != nil {
		log.Panicln(err)
	}
	err = InitPdfSigner()
	if err != nil {
		log.Panicln(err)
	}

	exitCode := m.Run()

	return exitCode
}

//go:embed sample.pdf
var samplePdfBytes []byte

func Test_postSign(t *testing.T) {
	body := bytes.NewBuffer(nil)

	mpw := multipart.NewWriter(body)

	partH := textproto.MIMEHeader{}
	partH.Set("Content-Type", "application/pdf")
	partW, err := mpw.CreatePart(partH)
	require.NoError(t, err)
	_, err = partW.Write(samplePdfBytes)
	require.NoError(t, err)

	partH = textproto.MIMEHeader{}
	partH.Set("Content-Type", "application/json; charset=UTF-8")
	partW, err = mpw.CreatePart(partH)
	require.NoError(t, err)
	signInfo := model.SignInfo{
		Type:   model.SignTypeCertification,
		DocMdp: model.DocMdpNoChanges,
		SignerInfo: model.SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Sealing",
			ContactInfo: "example@example.com",
		},
	}
	signInfoJsonBytes, err := json.Marshal(signInfo)
	require.NoError(t, err)
	_, err = partW.Write(signInfoJsonBytes)
	require.NoError(t, err)

	err = mpw.Close()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/sign", body)
	req.Header.Set("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%s", mpw.Boundary()))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", body.Len()))

	w := httptest.NewRecorder()
	postSign(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		resBodyBytes, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		t.Log(string(resBodyBytes))
	}
	require.Equal(t, http.StatusOK, res.StatusCode)

	outFile, err := os.Create("./sample-signed.pdf")
	require.NoError(t, err)

	defer func() { _ = outFile.Close() }()

	_, err = io.Copy(outFile, res.Body)
	require.NoError(t, err)
}
