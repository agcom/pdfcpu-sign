package handlers

import (
	"crypto"
	"errors"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/models"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/testutils"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"
)

func Test_adobePkcs7DetachedSigHandler_Sign(t *testing.T) {
	h := NewAdobePkcs7DetachedSigHandler(pvKey, cert, nil, crypto.SHA256)

	t.Run("certification", func(t *testing.T) {
		testSamples(t, h, newTestCertSig())
	})

	t.Run("approval", func(t *testing.T) {
		testSamples(t, h, newTestApprovalSig())
	})

	t.Run("approval over certification", func(t *testing.T) {
		certSig := newTestCertSig()
		certSig.References[0].TransformParams.(*models.TransformParamsDocMdp).Perm = models.DocMdpPermFormFillInAndPageTemplateInstAndSignAndAnnot

		certPdfPath := testSample(t, h, "../_samples/form-filled.pdf", certSig)

		approvalSig := newTestApprovalSig()
		testSample(t, h, certPdfPath, approvalSig)
	})
}

func testSamples(t *testing.T, h SigHandler, sig *models.Sig) {
	for _, sample := range samples {
		if strings.Contains(sample, "cert") {
			continue
		}

		t.Run(path.Base(sample), func(t *testing.T) {
			testSample(t, h, sample, sig)
		})
	}
}

func testSample(t *testing.T, h SigHandler, sample string, sig *models.Sig) string {
	// Read.

	readConf := model.NewDefaultConfiguration()
	readConf.WriteXRefStream = false // TODO: debug the problem when true.

	in, err := os.Open(sample)
	require.NoError(t, err)
	defer func(in *os.File) {
		_ = in.Close()
	}(in)

	ctx, err := api.ReadContext(in, readConf)
	require.NoError(t, err)

	// Initialize the output.

	out, err := os.CreateTemp(tmpDir, strings.TrimSuffix(path.Base(sample), path.Ext(sample))+"-signed-*.pdf")
	require.NoError(t, err)

	_, err = in.Seek(0, io.SeekStart)
	require.NoError(t, err)

	_, err = io.Copy(out, in)
	require.NoError(t, err)

	// Check for a final EOL.

	_, err = in.Seek(-1, io.SeekEnd)
	require.NoError(t, err)
	lastBytes := [1]byte{}
	_, err = in.Read(lastBytes[:])
	require.NoError(t, err)

	switch lastBytes[0] {
	case '\n', '\r':
		break
	default:
		_, err := out.Write([]byte{'\n'})
		require.NoError(t, err)
	}

	// Sign.

	err = h.Sign(ctx, sig)
	require.NoError(t, err)

	// Write the increment.

	err = api.WriteIncrement(ctx, out)
	require.NoError(t, err)

	// Relaxed validation

	outValidConf := model.NewDefaultConfiguration()

	outValidConf.ValidationMode = model.ValidationRelaxed
	err = api.Validate(out, outValidConf)
	require.NoError(t, err)

	// Strict validation
	// Skip the strict validation because of the pdfcpu being non-mature in this regard.
	// TODO: enable the strict validation if the pdfcpu becomes mature in validating.

	//outValidConf.ValidationMode = model.ValidationStrict
	//err = api.Validate(out, outValidConf)
	//require.NoError(t, err)

	// TODO: check the byte range.

	// TODO: use the qpdf C library instead of relying on the command line.
	qpdfOut, err := testutils.QpdfCheck(out.Name())
	if errors.Is(err, exec.ErrNotFound) {
		slog.Warn("The qpdf command is not available.")
	} else {
		require.NoError(t, err, qpdfOut)
	}

	return out.Name()
}

func newTestCertSig() *models.Sig {
	now := time.Now()
	sig := models.Sig{
		References: []*models.SigRef{{
			TransformMethod: models.TransformMethodDocMdp,
			TransformParams: &models.TransformParamsDocMdp{
				Perm: models.DocMdpPermNoChanges,
			},
		}},
		Time:        &now,
		Name:        "Alireza",
		Reason:      "Test",
		Location:    "Earth",
		ContactInfo: "example@example.com",
	}

	return &sig
}

func newTestApprovalSig() *models.Sig {
	now := time.Now()
	sig := models.Sig{
		Time:        &now,
		Name:        "Alireza",
		Reason:      "Test",
		Location:    "Earth",
		ContactInfo: "example@example.com",
	}

	return &sig
}
