package pdfcpusign

import "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

// TransformParams should either be TransformParamsDocMdp or TransformParamsFieldMdp.
type TransformParams interface {
	transformParams()

	ToPdfDict() types.Dict
}

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

func (tp *TransformParamsDocMdp) transformParams() {}
func (tp *TransformParamsDocMdp) ToPdfDict() types.Dict {
	dict := types.NewDict()

	dict["Type"] = types.Name("TransformParams") // FIXME: this can be absent.
	dict["P"] = types.Integer(tp.Perm)

	if tp.Version != "" && tp.Version != "1.2" { // Skip writing zero & default value.
		dict["V"] = types.Name(tp.Version)
	}

	return dict
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

func (tp *TransformParamsFieldMdp) transformParams() {}
func (tp *TransformParamsFieldMdp) ToPdfDict() types.Dict {
	dict := types.NewDict()

	//dict["Type"] = types.Name("TransformParams") // Can be absent.
	dict["Action"] = types.Name(tp.Action)
	switch tp.Action {
	case FieldMdpActionExclude, FieldMdpActionInclude:
		dict["Fields"] = types.NewStringLiteralArray(tp.Fields...)
	default:
		// NOP.
	}

	if tp.Version != "" && tp.Version != "1.2" { // Skip writing zero & default value.
		dict["V"] = types.Name(tp.Version)
	}

	return dict
}

// TODO: type SignatureReferenceTransformParamsUsageRights struct { ... }
