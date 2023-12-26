package signpdf

import (
	"crypto"
	"testing"
)

// Disabled, because it fails! The external library used in DigitorusPdfSigner is broken.
func disabledTestDigitorusPdfSigner_Sign(t *testing.T) {
	ps := NewDigitorusPdfSigner(pvKey.(crypto.Signer), cert, certChains)
	PdfSignerTests(t, ps)
}
