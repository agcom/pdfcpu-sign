package signpdf

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/agcom/pdfcpu-sign/internal/model"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/handlers"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/models"
	"github.com/digitorus/pdfsign/sign"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	pdfcpuModel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"io"
	"log/slog"
	"os"
)

type PdfCpuSignPdfSigner struct {
	h handlers.SigHandler
}

func NewPdfCpuSignPdfSigner(
	pvKey crypto.PrivateKey,
	cert *x509.Certificate,
	certParents []*x509.Certificate,
) *PdfCpuSignPdfSigner {
	return &PdfCpuSignPdfSigner{handlers.NewAdobePkcs7DetachedSigHandler(pvKey, cert, certParents, crypto.SHA512)}
}

func (ps *PdfCpuSignPdfSigner) Sign(input, output string, signInfo *model.SignInfo) error {
	// TODO: do the signing and writing to the output file asynchronously.

	optimInTmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("failed to create a temporary file for the optimized PDF file; %w", err)
	}
	defer func() {
		err := optimInTmpFile.Close()
		if err != nil {
			slog.Error("Failed to close a temporary file designated for optimizing a PDF file.", "error", err, "path", optimInTmpFile.Name())
		}
	}()

	optimConf := pdfcpuModel.NewDefaultConfiguration()
	optimConf.WriteXRefStream = false // TODO: remove this line after debugging the related issue.

	err = api.OptimizeFile(input, optimInTmpFile.Name(), optimConf)
	if err != nil {
		return fmt.Errorf("failed to optimize a PDF file; %w", err)
	}

	readConf := pdfcpuModel.NewDefaultConfiguration()
	readConf.WriteXRefStream = false // TODO: remove this line after debugging the related issue.

	pdfCtx, err := api.ReadContext(optimInTmpFile, readConf)
	if err != nil {
		return fmt.Errorf("failed to read a PDF file; %w", err)
	}

	err = ps.h.Sign(pdfCtx, signInfoToPdfCpuSig(signInfo))
	if err != nil {
		return fmt.Errorf("failed to sign a PDF; %w", err)
	}

	// Write to the output.

	out, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create the output file of a signed PDF; %w", err)
	}
	defer func() {
		err := out.Close()
		if err != nil {
			slog.Error("Failed to close a temporary file designated for a signed PDF output.", "error", err, "path", out.Name())
		}
	}()

	_, err = optimInTmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek a PDF file's reader; %w", err)
	}
	_, err = io.Copy(out, optimInTmpFile)
	if err != nil {
		return fmt.Errorf("failed to copy a PDF file's original content to its corresponding output signed PDF file; %w", err)
	}

	// Check for a final EOL.

	_, err = optimInTmpFile.Seek(-1, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek a PDF file's reader; %w", err)
	}
	lastBytes := [1]byte{}
	_, err = optimInTmpFile.Read(lastBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read the last byte of PDF file; %w", err)
	}

	switch lastBytes[0] {
	case '\n', '\r':
		break
	default:
		_, err := out.Write([]byte{'\n'})
		if err != nil {
			return fmt.Errorf("failed to write an EOL marker to a PDF file; %w", err)
		}
	}

	// Write the increment.
	err = api.WriteIncrement(pdfCtx, out)
	if err != nil {
		return fmt.Errorf("failed to write an incremental update of a PDF file; %w", err)
	}

	return nil
}

func signInfoToPdfCpuSig(signInfo *model.SignInfo) *models.Sig {
	sig := models.Sig{}

	sig.Name = signInfo.SignerInfo.Name
	sig.Reason = signInfo.SignerInfo.Reason
	sig.ContactInfo = signInfo.SignerInfo.ContactInfo
	sig.Location = signInfo.SignerInfo.Location
	sig.Time = &signInfo.SignerInfo.Date

	if signInfo.Type == sign.CertificationSignature {
		sig.References = []*models.SigRef{{
			TransformMethod: models.TransformMethodDocMdp,
			TransformParams: &models.TransformParamsDocMdp{
				Perm: docMdpToPdfCpuSignDocMdp(signInfo.DocMdp),
			},
		}}
	}

	return &sig
}

func docMdpToPdfCpuSignDocMdp(docMdp model.DocMdp) models.DocMdpPerm {
	switch docMdp {
	case model.DocMdpNoChanges:
		return models.DocMdpPermNoChanges
	case model.DocMdpFormSign:
		return models.DocMdpPermFormFillInAndPageTemplateInstAndSign
	case model.DocMdpAnnotFormSign:
		return models.DocMdpPermFormFillInAndPageTemplateInstAndSignAndAnnot
	}

	panic(fmt.Sprintf("invalid DocMDP=%s", docMdp))
}
