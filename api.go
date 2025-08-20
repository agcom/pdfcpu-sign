package pdfcpusign

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func SignPipe(h SigHandler, in io.ReadSeeker, out io.Writer, sig *Sig, incrOnly bool) error {
	if !incrOnly {
		_, err := in.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("seek to start: %w", err)
		}

		_, err = io.Copy(out, in)
		if err != nil {
			return fmt.Errorf("copy input bytes to ouptut: %w", err)
		}
	}

	pdfCtxConf := model.NewDefaultConfiguration()
	pdfCtxConf.WriteXRefStream = false // TODO: debug the problem when true.

	pdfCtx, err := pdfcpu.Read(in, pdfCtxConf)
	if err != nil {
		return fmt.Errorf("read PDF: %w", err)
	}

	err = h.Sign(pdfCtx, sig)
	if err != nil {
		return err
	}

	if !incrOnly {
		err = ensureEol(in, out)
		if err != nil {
			return err
		}
	}

	err = pdfcpuapi.WriteIncrement(pdfCtx, out)
	if err != nil {
		return fmt.Errorf("write increment: %w", err)
	}

	return nil
}

func SignFile(h SigHandler, in string, out string, sig *Sig) error {
	inFile, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer func() {
		err := inFile.Close()
		if err != nil {
			slog.Warn(fmt.Sprintf("Closing the opened input file \"%s\" failed: %s.", in, err))
			err = nil
		}
	}()

	outFile, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}

	err = SignPipe(h, inFile, outFile, sig, false)
	if err != nil {
		return err
	}

	return nil
}

// SignType defines the signature type to use.
type SignType string

const (
	// SignTypeCert is a signature type that can be applied once to a PDF document (it must be the first signature),
	// and is always to be associated with the DocMDP field.
	SignTypeCert SignType = "certification"

	// SignTypeApproval is a signature type that can be applied multiple times to a PDF document.
	SignTypeApproval = "approval"
)

// SignerInfo holds the signer (usually a person or a company) information;
// it is only designed to be used in unmarshal positions (and not marshal positions) regarding ser/deserialization.
type SignerInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Time        time.Time
}

// SignInfo holds a signing procedure information;
// it is only designed to be used in unmarshal positions (and not marshal positions) regarding ser/deserialization.
type SignInfo struct {
	Type       SignType
	DocMdp     DocMdpPerm
	SignerInfo *SignerInfo
}

func (si *SignInfo) ToSig() *Sig {
	sig := Sig{}

	if si.SignerInfo != nil {
		sig.Name = si.SignerInfo.Name
		sig.Reason = si.SignerInfo.Reason
		sig.ContactInfo = si.SignerInfo.ContactInfo
		sig.Location = si.SignerInfo.Location
		sig.Time = si.SignerInfo.Time
	}

	if si.Type == SignTypeCert {
		sig.References = []*SigRef{{
			TransformMethod: TransformMethodDocMdp,
			TransformParams: &TransformParamsDocMdp{
				Perm: si.DocMdp,
			},
		}}
	}

	return &sig
}
