package pdfcpusign

import (
	"fmt"
	"io"
	"log/slog"
	"os"

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
