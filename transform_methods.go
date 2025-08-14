package pdfcpu_sign

import "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

// TransformParams should either be TransformParamsDocMdp or TransformParamsFieldMdp.
type TransformParams any

type TransformMethod string

const (
	TransformMethodDocMdp      TransformMethod = "DocMDP"
	TransformMethodUsageRights TransformMethod = "UR"
	TransformMethodFieldMdp    TransformMethod = "FieldMDP"
)

type DocMdpPerm int

const (
	DocMdpPermNoChanges                                    DocMdpPerm = 1
	DocMdpPermFormFillInAndPageTemplateInstAndSign         DocMdpPerm = 2
	DocMdpPermFormFillInAndPageTemplateInstAndSignAndAnnot DocMdpPerm = 3
)

type TransformParamsDocMdp struct {
	Perm    DocMdpPerm
	Version string // V
}

func NewTransformParamsDocMdp() *TransformParamsDocMdp {
	return &TransformParamsDocMdp{ // Fill with specified default values if absent when reading a PDF file.
		Perm:    DocMdpPermFormFillInAndPageTemplateInstAndSign,
		Version: "1.2",
	}
}

func (tp *TransformParamsDocMdp) ToPdfDict() types.Dict {
	dict := types.NewDict()

	dict["Type"] = types.Name("TransformParams")
	dict["P"] = types.Integer(tp.Perm)

	if tp.Version != "" && tp.Version != "1.2" { // Skip writing zero & default value.
		dict["V"] = types.Name(tp.Version)
	}

	return dict
}

func (tp *TransformParamsDocMdp) ToPdfObj() types.Object {
	return tp.ToPdfDict()
}

type FieldMdpAction string

const (
	FieldMdpActionAll     FieldMdpAction = "All"
	FieldMdpActionInclude FieldMdpAction = "Include"
	FieldMdpActionExclude FieldMdpAction = "Exclude"
)

type TransformParamsFieldMdp struct {
	Action  FieldMdpAction
	Fields  []string
	Version string // V
}

func NewTransformParamsFieldMdp() *TransformParamsFieldMdp {
	// Fill in with default values if absent when reading a PDF file.
	return &TransformParamsFieldMdp{
		Version: "1.2",
	}
}

// TODO: type SignatureReferenceTransformParamsUsageRights struct { ... }
