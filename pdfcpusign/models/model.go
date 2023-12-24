package models

import "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

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
