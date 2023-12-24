package signpdf

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/digitorus/pdfsign/revocation"
	pdfsign "github.com/digitorus/pdfsign/sign"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"io"
	"log/slog"
	"os"
	"time"
)

type DigitorusPdfSigner struct {
	key        crypto.Signer
	cert       *x509.Certificate
	certChains [][]*x509.Certificate
}

func NewDigitorusPdfSigner(key crypto.Signer, cert *x509.Certificate, certChains [][]*x509.Certificate) *DigitorusPdfSigner {
	return &DigitorusPdfSigner{
		key:        key,
		cert:       cert,
		certChains: certChains,
	}
}

func (ps *DigitorusPdfSigner) Sign(input io.ReadSeeker, output io.Writer, signInfo *SignInfo) error {
	// Create a temporary output file.
	outTmp, err := os.CreateTemp("", "agcom-pdfcpu-sign-digitorus-pdf-signer-*")
	if err != nil {
		return fmt.Errorf("failed to create a temporary output file; %w", err)
	}
	defer func() {
		err := outTmp.Close()
		if err != nil {
			slog.Error("Closing a temporary output file failed.", "error", err, "path", outTmp.Name())
		}
		err = os.Remove(outTmp.Name())
		if err != nil {
			slog.Error("Removing a temporary output file failed.", "error", err, "path", outTmp.Name())
		}
	}()

	// Flush the input into a file if it is not already.
	if inputFile, ok := input.(*os.File); ok {
		err := ps.SignDigitorus(inputFile.Name(), outTmp.Name(), signInfo.ToDigitorusModel())
		if err != nil {
			return err
		}
	} else {
		inTmp, err := os.CreateTemp("", "agcom-pdfcpu-sign-digitorus-pdf-signer-*")
		if err != nil {
			return fmt.Errorf("failed to create the input temporary file; %w", err)
		}
		defer func() {
			err := outTmp.Close()
			if err != nil {
				slog.Error("Closing a temporary input file failed.", "error", err, "path", inTmp.Name())
			}
			err = os.Remove(outTmp.Name())
			if err != nil {
				slog.Error("Removing a temporary input file failed.", "error", err, "path", inTmp.Name())
			}
		}()

		err = ps.SignDigitorus(inTmp.Name(), outTmp.Name(), signInfo.ToDigitorusModel())
		if err != nil {
			return err
		}
	}

	// Flush the outTmp into the output.
	_, err = outTmp.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek the temporary output file; %w", err)
	}
	_, err = io.Copy(output, outTmp)
	if err != nil {
		return fmt.Errorf("failed to copy from a temporary file into the output; %w", err)
	}

	return nil
}

func (ps *DigitorusPdfSigner) SignDigitorus(input, output string, signData *pdfsign.SignDataSignature) error {
	signData.Info.Date = time.Now()

	// Read the PDF version.
	pdfCtx, err := pdfcpu.ReadFile(input, nil)
	if err != nil {
		return fmt.Errorf("reading the PDF file failed; %w", err)
	}
	ver := pdfCtx.VersionString()

	digestAlg, err := bestDigestAlgPdfVer(ver)
	if err != nil { // TODO: optimize the PDF input to bump the PDF version and support signing anyway.
		return fmt.Errorf("signing not supported; %w", err)
	}

	err = pdfsign.SignFile(input, output, pdfsign.SignData{
		Signature:         *signData,
		DigestAlgorithm:   digestAlg,
		Signer:            ps.key,
		Certificate:       ps.cert,
		CertificateChains: ps.certChains,
		TSA: pdfsign.TSA{
			URL: "https://freetsa.org/tsr",
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: pdfsign.DefaultEmbedRevocationStatusFunction,
	})

	if err != nil {
		return fmt.Errorf("signing failed; %w", err)
	}

	return nil
}

func (si *SignInfo) ToDigitorusModel() *pdfsign.SignDataSignature {
	return &pdfsign.SignDataSignature{
		CertType:   si.Type.ToDigitorusModel(),
		DocMDPPerm: si.DocMdp.ToDigitorusModel(),
		Info: pdfsign.SignDataSignatureInfo{
			Name:        si.SignerInfo.Name,
			Location:    si.SignerInfo.Location,
			Reason:      si.SignerInfo.Reason,
			ContactInfo: si.SignerInfo.ContactInfo,
			Date:        si.SignerInfo.Date,
		},
	}
}

func (st SignType) ToDigitorusModel() uint {
	switch st {
	case SignTypeCert:
		return pdfsign.CertificationSignature
	case SignTypeApproval:
		return pdfsign.ApprovalSignature
	}

	panic(fmt.Sprintf("invalid SignType enum value %q", st))
}

func (dm DocMdp) ToDigitorusModel() uint {
	switch dm {
	case DocMdpNoChanges:
		return pdfsign.DoNotAllowAnyChangesPerms
	case DocMdpFormSign:
		return pdfsign.AllowFillingExistingFormFieldsAndSignaturesPerms
	case DocMdpFormSignAnnot:
		return pdfsign.AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
	case "":
		return 0
	}

	panic(fmt.Sprintf("invalid DocMdp enum value %q", dm))
}
