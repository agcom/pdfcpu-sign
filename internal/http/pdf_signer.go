package http

import (
	"crypto/x509"
	"errors"
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"github.com/agcom/pdfcpu-sign/internal/signpdf"
	"log/slog"
)

// TODO: move this to a more appropriate place?
var pdfSigner signpdf.PdfSigner

func InitPdfSigner() error {
	var trustChain []*x509.Certificate

	trustChains, err := p11.Cert.Verify(x509.VerifyOptions{})
	if err != nil {
		var systemRootErr x509.SystemRootsError
		if errors.As(err, &systemRootErr) {
			slog.Warn("Unable to get system roots to build a certificate trust chain by verifying the certificate.", "error", err)
		}
	} else {
		trustChain = trustChains[0][1:]
	}

	pdfSigner = signpdf.NewPdfCpuSignPdfSigner(p11.Key, p11.Cert, trustChain)
	return nil
}
