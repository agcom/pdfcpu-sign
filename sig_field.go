package pdfcpu_sign

import (
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

type FieldFlags uint32

const (
	FieldFlagReadOnly FieldFlags = 1 << iota
	FieldFlagRequired
	FieldFlagNoExport
)

type SigFieldLock struct {
	Action FieldMdpAction
	Fields []string
	Perm   DocMdpPerm
}

func (s *SigFieldLock) ToPdfDict() types.Dict {
	dict := types.NewDict()

	dict["Type"] = types.Name("SigFieldLock")
	dict["Action"] = types.Name(s.Action)
	if s.Fields != nil {
		dict["Fields"] = types.NewStringLiteralArray(s.Fields...)
	}
	if s.Perm != 0 {
		dict["P"] = types.Integer(s.Perm)
	}

	return dict
}

type SigField struct {
	Page              *types.IndirectRef // P
	Parent            *types.IndirectRef
	Kids              []types.IndirectRef
	PartialName       string             // T
	AlternativeName   string             // TU
	MappingName       string             // TM
	FieldFlags        FieldFlags         // Ff
	Value             *types.IndirectRef // V. TODO: facilitate having a direct value.
	DefaultValue      *Sig               // DV. TODO: can a signature field have a default value?
	AdditionalActions types.Dict         // AA. TODO: create its corresponding struct.
	Lock              *types.IndirectRef
	SeedValue         *types.IndirectRef // SV. TODO: create its corresponding struct.
}

func (sf *SigField) ToPdfDict() types.Dict {
	dict := types.NewDict()

	// Annotation related entries
	dict["Type"] = types.Name("Annot")
	dict["Subtype"] = types.Name(model.AnnotTypeStrings[model.AnnWidget])
	dict["Rect"] = types.NewIntegerArray(0, 0, 0, 0)
	dict["F"] = types.Integer(model.AnnHidden)
	if sf.Page != nil {
		dict["P"] = *sf.Page
	}

	dict["FT"] = types.Name("Sig")

	if sf.Parent != nil {
		dict["Parent"] = sf.Parent
	}

	if sf.Kids != nil {
		arr := make(types.Array, 0, len(sf.Kids))
		for _, kid := range sf.Kids {
			arr = append(arr, kid)
		}

		dict["Kids"] = arr
	}

	if sf.PartialName != "" {
		dict["T"] = types.StringLiteral(sf.PartialName)
	}

	if sf.AlternativeName != "" {
		dict["TU"] = types.StringLiteral(sf.AlternativeName)
	}

	if sf.MappingName != "" {
		dict["TM"] = types.StringLiteral(sf.MappingName)
	}

	if sf.FieldFlags != 0 {
		dict["Ff"] = types.Integer(sf.FieldFlags)
	}

	if sf.Value != nil {
		dict["V"] = *sf.Value
	}

	if sf.DefaultValue != nil {
		dict["DV"] = sf.DefaultValue.ToPdfDict()
	}

	if sf.AdditionalActions != nil {
		dict["AA"] = sf.AdditionalActions
	}

	if sf.Lock != nil {
		dict["Lock"] = sf.Lock
	}

	if sf.SeedValue != nil {
		dict["SV"] = sf.SeedValue
	}

	return dict
}

// TODO: define the Field type and embed into SigField.
// TODO: define the Annotation type and embed into AnnotationWidget.
// TODO: define the AnnotationWidget type.
// TODO: facilitate the functionality to sign an already existing field (should probably separate the Field struct).
// TODO: facilitate relaxed PDF reading regarding to direct and indirect objects (the current implementation assumes strict PDF reading).
// TODO: facilitate adding visual signatures through widget annotation embedding into signature field.
