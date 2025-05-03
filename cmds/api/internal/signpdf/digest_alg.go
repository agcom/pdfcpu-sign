package signpdf

import (
	"crypto"
	"fmt"
)

// bestDigestAlgPdfVer returns the most secure digest/hash algorithm supported in the specified PDF version (ver).
// Returns an error if the specified PDF version does not support digital signatures and panics if it is invalid.
// Sources:
// - Supported Standards — Acrobat Desktop  Digital Signature Guide: https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/standards.html
// - Section 6.3.5 - Digital Signatures in a PDF - Adobe : https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf
// - PDF Specification Index – PDF Association: https://pdfa.org/resource/pdf-specification-index/
// - History of PDF - Wikipedia: https://en.wikipedia.org/wiki/History_of_PDF
func bestDigestAlgPdfVer(ver string) (crypto.Hash, error) {
	switch ver {
	case "1.0", "1.1", "1.2":
		return 0, newUnsuppPdfVerErr(ver)
	case "1.3", "1.4", "1.5":
		return crypto.SHA1, nil
	case "1.6":
		return crypto.SHA256, nil
	case "1.7", "2.0":
		return crypto.SHA512, nil
	default:
		panic(fmt.Sprintf("invalid PDF version \"%s\"", ver))
	}
}

type unsuppPdfVerErr struct {
	Ver string
}

func (err unsuppPdfVerErr) Error() string {
	return fmt.Sprintf("PDF version %s does not support digital signatures", err.Ver)
}

func newUnsuppPdfVerErr(ver string) unsuppPdfVerErr {
	return unsuppPdfVerErr{Ver: ver}
}
