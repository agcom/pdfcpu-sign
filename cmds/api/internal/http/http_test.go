package http

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/agcom/pdfcpu-sign/cmds/api/internal/pkcs11"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/signpdf"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/testutils"
	pdfcpusigntestutils "github.com/agcom/pdfcpu-sign/testutils"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(mainDeferSafe(m))
}

// mainDeferSafe would not call os.Exit and therefore gives the cleanup defer functions to behave.
func mainDeferSafe(m *testing.M) int {
	crypto11Ctx, err := pkcs11.GetCrypt11Ctx()
	if err != nil {
		log.Panicln(err)
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

		err = key.Delete()
		if err != nil {
			slog.Error(
				"Deleting the test key pair failed.",
				"keyIdBase64",
				base64.StdEncoding.EncodeToString(kertId),
			)
		}
	}()

	pvKey, _, cert, err := pkcs11.GetKert(kertId, "")
	if err != nil {
		log.Panicf("Finding the just now created kert failed; %v.\n", err)
	}

	pdfSigner = signpdf.NewPdfCpuSignPdfSigner(pvKey, cert, nil)

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
	partH.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "pdf-file", "filename": "sample.pdf"}))

	partW, err := mpw.CreatePart(partH)
	require.NoError(t, err)

	_, err = partW.Write(samplePdfBytes)
	require.NoError(t, err)

	partH = textproto.MIMEHeader{}
	partH.Set("Content-Type", "application/json; charset=UTF-8")
	partH.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "sign-info"}))

	partW, err = mpw.CreatePart(partH)
	require.NoError(t, err)

	signInfo := signpdf.SignInfo{
		Type:   signpdf.SignTypeCert,
		DocMdp: signpdf.DocMdpNoChanges,
		SignerInfo: &signpdf.SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Test",
			ContactInfo: "example@example.org",
			Time:        time.Now(),
		},
	}
	signInfoJsonBytes, err := json.Marshal(signInfo)
	require.NoError(t, err)

	_, err = partW.Write(signInfoJsonBytes)
	require.NoError(t, err)

	err = mpw.Close()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/sign", body)
	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", mpw.Boundary()))
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

	err = pdfcpu.ValidateFile(outFile.Name(), nil)
	require.NoError(t, err)

	err = pdfcpusigntestutils.PdfCpuStrictValid(outFile)
	if err != nil {
		slog.Warn(fmt.Sprintf("The pdfcpu strict validation failed; %v.", err))
	}

	if qpdfOut, err := pdfcpusigntestutils.QpdfCheck(outFile.Name()); errors.Is(err, exec.ErrNotFound) {
		slog.Warn("The qpdf command is not available.")
	} else {
		require.NoError(t, err, qpdfOut)
	}
}
