package pdfcpusign

import (
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

type SigHandler interface {
	// TODO: facilitate signing already existing signature field, and/or providing the signature field properties.

	// Sign
	// Beware that after calling this function, you should only call api.WriteIncrement on the given context.
	Sign(pdfCtx *model.Context, sig *Sig) error
}

// TODO: facilitate honoring the signature seed value dictionary (when the user want to sign an existing signature field) that dictates how to sign a PDF document.
