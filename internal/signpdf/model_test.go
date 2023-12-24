package signpdf

import (
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/stretchr/testify/require"
	"testing"
)

func PdfSignerTests(t *testing.T, ps PdfSigner) {
	// TODO: more samples.
	// TODO: write the signed PDF to a temporary file.

	err := ps.Sign("./sample.pdf", "./sample-signed.pdf", newTestCertSignInfo())
	require.NoError(t, err)

	// Validate the output PDF file.
	err = pdfcpu.ValidateFile("./sample-signed.pdf", nil)
	require.NoError(t, err)

	// TODO: check via qpdf.
}
