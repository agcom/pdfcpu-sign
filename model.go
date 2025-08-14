package pdfcpu_sign

import (
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// TODO: get rid of these base interface if possible.

type PdfModel interface {
	ToPdfObj() types.Object
}

type PdfDictModel interface {
	PdfModel
	ToPdfDict() types.Dict
}

type PdfArrModel interface {
	PdfModel
	ToPdfArr() types.Array
}
