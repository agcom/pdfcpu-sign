package testutils

import (
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"io"
)

var strictValidConf = model.NewDefaultConfiguration()

func init() {
	strictValidConf.ValidationMode = model.ValidationStrict
}

func PdfCpuStrictValid(rs io.ReadSeeker) error {
	return pdfcpu.Validate(rs, strictValidConf)
}
