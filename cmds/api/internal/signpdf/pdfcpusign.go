package signpdf

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/handlers"
	"github.com/agcom/pdfcpu-sign/pdfcpusign/models"
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

func (ps *PdfCpuSignPdfSigner) Sign(input io.ReadSeeker, output io.Writer, signInfo *SignInfo) error {
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

		err = os.Remove(optimInTmpFile.Name())
		if err != nil {
			slog.Error("Failed to remove the temporary file designated for optimizing a PDF file.", "error", err, "path", optimInTmpFile.Name())
		}
	}()

	optimConf := pdfcpuModel.NewDefaultConfiguration()
	optimConf.WriteXRefStream = false

	err = api.Optimize(input, optimInTmpFile, optimConf)
	if err != nil {
		return fmt.Errorf("failed to optimize the PDF; %w", err)
	}

	readConf := pdfcpuModel.NewDefaultConfiguration()
	readConf.WriteXRefStream = false

	pdfCtx, err := api.ReadContext(optimInTmpFile, readConf)
	if err != nil {
		return fmt.Errorf("failed to read the PDF optimized file; %w", err)
	}

	err = ps.h.Sign(pdfCtx, signInfoToPdfCpuSignSig(signInfo))
	if err != nil {
		return fmt.Errorf("failed to sign the PDF; %w", err)
	}

	// Write to the output.

	_, err = optimInTmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek the optimized PDF file's reader; %w", err)
	}
	_, err = io.Copy(output, optimInTmpFile)
	if err != nil {
		return fmt.Errorf("failed to copy the PDF file's original content to the output; %w", err)
	}

	// Check for a final EOL.

	_, err = optimInTmpFile.Seek(-1, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek the optimized PDF file's reader; %w", err)
	}
	lastBytes := [1]byte{}
	_, err = optimInTmpFile.Read(lastBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read the last byte of the optimized PDF file; %w", err)
	}

	switch lastBytes[0] {
	case '\n', '\r':
		break
	default:
		_, err := output.Write([]byte{'\n'})
		if err != nil {
			return fmt.Errorf("failed to write an EOL marker to the output; %w", err)
		}
	}

	// Write the increment.
	err = api.WriteIncrement(pdfCtx, output)
	if err != nil {
		return fmt.Errorf("failed to write the incremental update to the output; %w", err)
	}

	return nil
}

func signInfoToPdfCpuSignSig(signInfo *SignInfo) *models.Sig {
	sig := models.Sig{}

	if signInfo.SignerInfo != nil {
		sig.Name = signInfo.SignerInfo.Name
		sig.Reason = signInfo.SignerInfo.Reason
		sig.ContactInfo = signInfo.SignerInfo.ContactInfo
		sig.Location = signInfo.SignerInfo.Location
		sig.Time = signInfo.SignerInfo.Time
	}

	if signInfo.Type == SignTypeCert {
		sig.References = []*models.SigRef{{
			TransformMethod: models.TransformMethodDocMdp,
			TransformParams: &models.TransformParamsDocMdp{
				Perm: docMdpToPdfCpuSignDocMdp(signInfo.DocMdp),
			},
		}}
	}

	return &sig
}

func docMdpToPdfCpuSignDocMdp(docMdp DocMdp) models.DocMdpPerm {
	switch docMdp {
	case DocMdpNoChanges:
		return models.DocMdpPermNoChanges
	case DocMdpFormSign:
		return models.DocMdpPermFormFillInAndPageTemplateInstAndSign
	case DocMdpFormSignAnnot:
		return models.DocMdpPermFormFillInAndPageTemplateInstAndSignAndAnnot
	}

	panic(fmt.Sprintf("invalid DocMDP=%s", docMdp))
}
