package pdfcpusign

import (
	"crypto"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignFile(t *testing.T) {
	tmpDir := t.TempDir()
	h := NewAdobePkcs7DetachedSigHandler(pvKey, cert, nil, crypto.SHA256)

	for _, sample := range samples {
		t.Run(sample, func(t *testing.T) {
			signedSample := path.Join(tmpDir, path.Base(sample))

			err := SignFile(h, sample, signedSample, &Sig{})
			require.NoError(t, err)

			validatePdfFile(t, signedSample)
		})
	}
}
