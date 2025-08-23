package pdfcpusign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/agcom/pdfcpu-sign/testutils"
	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testWithSamples(t *testing.T, h SigHandler, sig *Sig) {
	for _, sample := range samples {
		t.Run(path.Base(sample), func(t *testing.T) {
			testWithSample(t, h, sample, sig)
		})
	}
}

func testWithSample(t *testing.T, h SigHandler, sample string, sig *Sig) string {
	// Read.

	in, err := os.Open(sample)
	require.NoError(t, err)
	defer func() {
		err := in.Close()
		if err != nil {
			slog.Warn(fmt.Sprintf("Closing the opened sample file \"%s\" failed: %s.", sample, err))
			err = nil
		}
	}()

	// Initialize the output buffer.

	outBuf := bytes.NewBuffer(nil)

	inStats, err := in.Stat()
	require.NoError(t, err)

	outBuf.Grow(int(inStats.Size()))

	// Copy the original PDF bytes to the output buffer.

	_, err = in.Seek(0, io.SeekStart)
	require.NoError(t, err)

	_, err = io.Copy(outBuf, in)
	require.NoError(t, err)

	// Ensure a final EOL before writing the increment.

	err = ensureEol(in, outBuf)
	require.NoError(t, err)

	// Read the original PDF.

	pdfCtxConf := model.NewDefaultConfiguration()
	pdfCtxConf.WriteXRefStream = false // TODO: debug the problem when true.

	pdfCtx, err := pdfcpu.Read(in, pdfCtxConf)
	require.NoError(t, err)

	// Sign.

	err = h.Sign(pdfCtx, sig)
	require.NoError(t, err)

	// Write the increment.

	err = pdfcpuapi.WriteIncrement(pdfCtx, outBuf)
	require.NoError(t, err)

	// Write the output to a temporary file, for calling the validation procedure and returning the signed PDF file's path for further external tests if any.

	outBytes := outBuf.Bytes()
	outRs := bytes.NewReader(outBytes)

	outFile, err := os.CreateTemp(tmpDir, strings.TrimSuffix(path.Base(sample), path.Ext(sample))+"-signed-*.pdf")
	require.NoError(t, err)
	defer func() {
		err := outFile.Close()
		if err != nil {
			slog.Warn(fmt.Sprintf("Closing the temporary output file \"%s\" failed: %s.", outFile.Name(), err))
			err = nil
		}
	}()

	_, err = outRs.Seek(0, io.SeekStart)
	require.NoError(t, err)
	_, err = io.Copy(outFile, outRs)
	require.NoError(t, err)
	err = outFile.Sync()
	require.NoError(t, err)

	validatePdfFile(t, outFile.Name())

	return outFile.Name()
}

func newTestCertSig() *Sig {
	sig := Sig{
		References: []*SigRef{{
			TransformMethod: TransformMethodDocMdp,
			TransformParams: &TransformParamsDocMdp{
				Perm: DocMdpPermNoChanges,
			},
		}},
		Time:        time.Now(),
		Name:        "Alireza",
		Reason:      "Test",
		Location:    "Earth",
		ContactInfo: "example@example.org",
	}

	return &sig
}

func newTestApprovalSig() *Sig {
	sig := Sig{
		Time:        time.Now(),
		Name:        "Alireza",
		Reason:      "Test",
		Location:    "Earth",
		ContactInfo: "example@example.org",
	}

	return &sig
}

func validatePdfFile(t *testing.T, f string) {
	// PDFCPU relaxed validation.

	validConf := model.NewDefaultConfiguration()
	validConf.ValidationMode = model.ValidationRelaxed

	err := pdfcpuapi.ValidateFile(f, validConf)
	assert.NoError(t, err)
	err = nil

	// PDFCPU strict validation.

	validConf.ValidationMode = model.ValidationStrict

	err = pdfcpuapi.ValidateFile(f, validConf)
	if err != nil {
		// TODO: enforce this validation; currently not enforced due to always reporting the `dict=type1FontDict required entry=FirstChar missing` validation error.
		slog.Warn(fmt.Sprintf("Strict validation failed: %s.", err))
	}

	// QPDF validation.

	qpdfOut, err := testutils.QpdfCheck(f)
	if errors.Is(err, exec.ErrNotFound) {
		slog.Warn("The qpdf command is not available; skipping its validations.")
	} else {
		assert.NoError(t, err, qpdfOut)
		err = nil
	}
}
