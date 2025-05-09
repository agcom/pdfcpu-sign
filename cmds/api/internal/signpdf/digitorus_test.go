package signpdf

import (
	"crypto"
	"testing"
)

func TestDigitorusPdfSigner_Sign(t *testing.T) {
	ps := NewDigitorusPdfSigner(pvKey.(crypto.Signer), cert, certChains)
	PdfSignerTests(t, ps)
}
