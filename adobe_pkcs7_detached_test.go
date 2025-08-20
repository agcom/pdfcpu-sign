package pdfcpusign

import (
	"crypto"
	"testing"
)

func Test_adobePkcs7DetachedSigHandler_Sign(t *testing.T) {
	h := NewAdobePkcs7DetachedSigHandler(pvKey, cert, nil, crypto.SHA256)

	t.Run("certification", func(t *testing.T) {
		testWithSamples(t, h, newTestCertSig())
	})

	t.Run("approval", func(t *testing.T) {
		testWithSamples(t, h, newTestApprovalSig())
	})

	t.Run("approval over certification", func(t *testing.T) {
		certSig := newTestCertSig()
		certSig.References[0].TransformParams.(*TransformParamsDocMdp).Perm = DocMdpPermFormFillInAndPageTemplateInstAndSignAndAnnot

		certPdfPath := testWithSample(t, h, "./_samples/form-filled.pdf", certSig)

		approvalSig := newTestApprovalSig()
		testWithSample(t, h, certPdfPath, approvalSig)
	})
}
