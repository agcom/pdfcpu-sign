package signpdf

import "github.com/agcom/pdfcpu-sign/internal/model"

type PdfSigner interface {
	Sign(input, output string, signInfo *model.SignInfo) error
}
