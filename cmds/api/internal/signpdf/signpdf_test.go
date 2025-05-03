package signpdf

import (
	"errors"
	"fmt"
	pdfcpusigntestutils "github.com/agcom/pdfcpu-sign/testutils"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/stretchr/testify/require"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"
)

func PdfSignerTests(t *testing.T, ps PdfSigner) {
	const pdfCpuSignSamplesDir = "./../../../../_samples/"
	samplesEntries, err := os.ReadDir(pdfCpuSignSamplesDir)
	require.NoError(t, err)

	for _, sampleEntry := range samplesEntries {
		sample := path.Join(pdfCpuSignSamplesDir, sampleEntry.Name())
		t.Run(path.Base(sample), func(t *testing.T) {
			testSample(t, ps, sample, newTestCertSignInfo())
		})
	}

	t.Run("approval over certification", func(t *testing.T) {
		sample := "./sample.pdf"

		certSignInfo := newTestCertSignInfo()
		certSignInfo.DocMdp = DocMdpFormSignAnnot

		testSample(t, ps, sample, certSignInfo)
		testSample(t, ps, sample, newTestApprovalSignInfo())
	})
}

func testSample(t *testing.T, ps PdfSigner, sample string, signInfo *SignInfo) {
	in, err := os.Open(sample)
	require.NoError(t, err)
	defer func() {
		_ = in.Close()
	}()

	out, err := os.CreateTemp(tmpDir, strings.TrimSuffix(path.Base(sample), path.Ext(sample)))
	require.NoError(t, err)
	defer func() {
		_ = out.Close()
		_ = os.Remove(out.Name())
	}()

	err = ps.Sign(in, out, signInfo)
	require.NoError(t, err)

	// Validate the output PDF file.
	err = pdfcpu.Validate(out, nil)
	require.NoError(t, err)

	err = pdfcpusigntestutils.PdfCpuStrictValid(out)
	if err != nil { // Only log; no require; because the strict validation is not necessary for a PDF file to be considered OK.
		slog.Warn(fmt.Sprintf("The pdfcpu strict validation failed; %s.", err))
	}

	// Check using QPDF.
	qpdfOut, err := pdfcpusigntestutils.QpdfCheck(out.Name())
	if errors.Is(err, exec.ErrNotFound) {
		slog.Warn("The qpdf command is not available.")
	} else {
		require.NoError(t, err, qpdfOut)
	}
}

func newTestCertSignInfo() *SignInfo {
	return &SignInfo{
		Type:   SignTypeCert,
		DocMdp: DocMdpNoChanges,
		SignerInfo: &SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Test",
			ContactInfo: "example@exmaple.com",
			Time:        time.Now(),
		},
	}
}

func newTestApprovalSignInfo() *SignInfo {
	return &SignInfo{
		Type: SignTypeApproval,
		SignerInfo: &SignerInfo{
			Name:        "Alireza",
			Location:    "Earth",
			Reason:      "Test",
			ContactInfo: "example@exmaple.com",
			Time:        time.Now(),
		},
	}
}
