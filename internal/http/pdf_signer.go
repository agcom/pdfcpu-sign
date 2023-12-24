package http

import (
	"crypto/x509"
	"fmt"
	"github.com/agcom/pdfcpu-sign/internal/pkcs11"
	"github.com/agcom/pdfcpu-sign/internal/signpdf"
	"log/slog"
)

// TODO: move this to a more appropriate place?
var pdfSigner signpdf.PdfSigner

func InitPdfSigner() error {
	pvKey, _, cert, err := pkcs11.GetKertByConf()
	if err != nil {
		return fmt.Errorf("failed to get kert; %w", err)
	}

	// Try to verify the certificate using system roots.
	var trustChain []*x509.Certificate
	if trustChains, err := cert.Verify(x509.VerifyOptions{}); err != nil {
		slog.Warn("Unable to build a certificate trust chain by using system roots.", "error", err)
		slog.Warn("Assuming that the certificate is self-signed.")
		trustChain = []*x509.Certificate{cert}
	} else {
		trustChain = trustChains[0][1:]
	}

	pdfSigner = signpdf.NewPdfCpuSignPdfSigner(pvKey, cert, trustChain[1:])
	return nil
}
