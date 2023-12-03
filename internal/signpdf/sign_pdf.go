// TODO: promote the package to a decoupled package?
package signpdf

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/agcom/pdfcpu-sign/internal/model"
	"github.com/digitorus/pdfsign/revocation"
	pdfsign "github.com/digitorus/pdfsign/sign"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"time"
)

type PdfSigner struct {
	Key             crypto.Signer
	Cert            *x509.Certificate
	certChainsCache [][]*x509.Certificate
}

func NewPdfSigner(key crypto.Signer, cert *x509.Certificate) *PdfSigner {
	return &PdfSigner{
		Key:  key,
		Cert: cert,
	}
}

// Sign function signs the input PDF file and writes it to the output (calls os.Create on the output file).
func (ps *PdfSigner) Sign(input, output string, signData *pdfsign.SignDataSignature) error {
	// TODO: ctx function parameter.
	// TODO: authenticate the signature information (signInfo)?
	signData.Info.Date = time.Now() // TODO: let the user reset the sign date.

	// Read the PDF version.
	pdfCtx, err := pdfcpu.ReadFile(input, nil)
	if err != nil {
		return fmt.Errorf("reading the PDF file failed (might be an invalid PDF file); %w", err)
	}
	ver := pdfCtx.VersionString()

	digestAlg, err := bestDigestAlgPdfVer(ver)
	if err != nil {
		return fmt.Errorf("signing not supported; %w", err)
	}

	certChains, err := ps.ensureCertChainsCache()
	if err != nil {
		return fmt.Errorf("failed to obtain certificate chains of trust; %w", err)
	}

	err = pdfsign.SignFile(input, output, pdfsign.SignData{
		Signature:         *signData,
		DigestAlgorithm:   digestAlg,
		Signer:            ps.Key,
		Certificate:       ps.Cert,
		CertificateChains: certChains,
		TSA: pdfsign.TSA{
			URL: "https://freetsa.org/tsr",
		},
		RevocationData:     revocation.InfoArchival{}, // TODO: figure out revocation fields (from the product manager); also, these two fields are explicitly experimental.
		RevocationFunction: pdfsign.DefaultEmbedRevocationStatusFunction,
	})

	if err != nil {
		return fmt.Errorf("signing failed; %w", err)
	}

	return nil
}

func (ps *PdfSigner) SignModel(input, output string, signInfo *model.SignInfo) error {
	return ps.Sign(input, output, signInfo.ToOldModel())
}

var TestCertRoots *x509.CertPool = nil

func (ps *PdfSigner) ensureCertChainsCache() ([][]*x509.Certificate, error) {
	chains := ps.certChainsCache
	if chains != nil {
		return chains, nil
	}

	chains, err := ps.Cert.Verify(x509.VerifyOptions{Roots: TestCertRoots})
	if err != nil {
		return nil, fmt.Errorf("verifying certificate failed; %w", err)
	}

	ps.certChainsCache = chains
	return chains, nil
}
