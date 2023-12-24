// TODO: promote the package to decoupled?
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

func (ps *DigitorusPdfSigner) Sign(input, output string, signInfo *model.SignInfo) error {
	return ps.SignDigitorus(input, output, signInfo.ToDigitorusModel())
}

func (ps *DigitorusPdfSigner) SignDigitorus(input, output string, signData *pdfsign.SignDataSignature) error {
	signData.Info.Date = time.Now()

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

	ps.tryFillCertChainsIfNil()
	if err != nil {
		return fmt.Errorf("failed to obtain certificate chains of trust; %w", err)
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

var TestCertRoots *x509.CertPool = nil

func (ps *DigitorusPdfSigner) tryFillCertChainsIfNil() {
	if ps.certChains != nil {
		return
	}

	ps.certChains, _ = ps.cert.Verify(x509.VerifyOptions{Roots: TestCertRoots})
}
