package signpdf

import (
	"testing"
)

func TestPdfCpuSignPdfSigner_Sign(t *testing.T) {
	ps := NewPdfCpuSignPdfSigner(pvKey, cert, certChains[0][1:])
	PdfSignerTests(t, ps)
}
