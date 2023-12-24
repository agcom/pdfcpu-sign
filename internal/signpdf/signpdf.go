package signpdf

import (
	"io"
)

type PdfSigner interface {
	Sign(input io.ReadSeeker, output io.Writer, signInfo *SignInfo) error
}
