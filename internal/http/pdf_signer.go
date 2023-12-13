package http

import (
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"github.com/agcom/pdfcpu-sign/internal/signpdf"
)

// TODO: move this to a more appropriate place?
var pdfSigner *signpdf.PdfSigner

func InitPdfSigner() error {
	pdfSigner = signpdf.NewPdfSigner(p11.Key, p11.Cert)

	return nil
}
