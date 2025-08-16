package pdfcpusign

import (
	"crypto"
	"crypto/x509"
	"strings"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

type SigType string

const (
	SigTypeSig          SigType = "Sig"
	SigTypeDocTimeStamp SigType = "DocTimeStamp"
)

const (
	SubFilterAdobeX509RsaSha1   = "adbe.x509.rsa_sha1" // Deprecated in PDF 2.0.
	SubFilterAdobePkcs7Sha1     = "adbe.pkcs7.sha1"    // Deprecated in PDF 2.0.
	SubFilterAdobePkcs7Detached = "adbe.pkcs7.detached"
	SubFilterEtsiCadesDetached  = "ETSI.CAdES.detached" // >= PDF 2.0.
	SubFilterEtsiRfc3161        = "ETSI.RFC3161"        // >= PDF 2.0; For TypeDocTimeStamp.
)

const (
	FilterAdobePpkLite  = "Adobe.PPKLite"
	FilterAdobePpkms    = "Adobe.PPKMS"
	FilterEntrustPpkef  = "Entrust.PPKEF"
	FilterCiciSignIt    = "CICI.SignIt"
	FilterVeriSignPpkvs = "VeriSign.PPKVS"
)

type SigChanges struct {
	PagesAltered   int
	FieldsAltered  int
	FieldsFilledIn int
}

func (sc *SigChanges) ToPdfArr() types.Array {
	return types.NewIntegerArray(sc.PagesAltered, sc.FieldsAltered, sc.FieldsFilledIn)
}

type PropAuthType string

const (
	PropAuthTypePin         PropAuthType = "PIN"
	PropAuthTypePassword    PropAuthType = "Password"
	PropAuthTypeFingerprint PropAuthType = "Fingerprint"
)

type SigRef struct {
	TransformMethod TransformMethod
	TransformParams TransformParams // TODO: this can also be an indirect reference.
	Data            *types.IndirectRef
	DigestMethod    crypto.Hash // Deprecated in PDF 2.0. TODO: this value is way more limited than crypto.Hash available values.
}

func (sr *SigRef) ToPdfDict() types.Dict {
	dict := types.NewDict()

	dict["Type"] = types.Name("SigRef")

	dict["TransformMethod"] = types.Name(sr.TransformMethod)

	if sr.TransformParams != nil {
		dict["TransformParams"] = sr.TransformParams.ToPdfDict()
	}
	if sr.Data != nil {
		dict["Data"] = *sr.Data
	}

	if sr.DigestMethod != 0 {
		dict["DigestMethod"] = types.Name(strings.ReplaceAll(sr.DigestMethod.String(), "-", ""))
	}

	return dict
}

type Sig struct {
	Type      SigType
	Filter    string
	SubFilter string

	// Key information & signature value

	Cert     []*x509.Certificate
	Contents []byte

	// Reference

	References []*SigRef // TODO: facilitate allowing indirect references to the signature reference dictionaries (only if ByteRange is not present).
	ByteRange  []int64

	// Signature properties

	HandlerVersion *int      // R; Deprecated in PDF 2.0.
	Time           time.Time // M
	Name           string
	Reason         string
	Location       string
	PropBuild      types.Dict // TODO: create its corresponding struct.
	PropAuthTime   *int
	PropAuthType   PropAuthType

	Changes       *SigChanges
	ContactInfo   string
	FormatVersion int // V
}

func (s *Sig) ToPdfDict() types.Dict {
	dict := types.NewDict()

	dict["Type"] = types.Name(s.Type)

	dict["Filter"] = types.Name(s.Filter)

	if s.SubFilter != "" {
		dict["SubFilter"] = types.Name(s.SubFilter)
	}

	dict["Contents"] = types.NewHexLiteral(s.Contents)

	if s.Cert != nil {
		panic("Signature dictionary Cert entry is not yet implemented.")
	}

	if s.ByteRange != nil {
		intByteRange := make([]int, len(s.ByteRange))
		for i, e := range s.ByteRange {
			intByteRange[i] = int(e)
		}
		// TODO: incorporate int64/uint64 (and other possible array element types other than defined primitive types) into pdfcpu.
		// FIXME: write with strPdfArrElem as a hack solution.
		dict["ByteRange"] = types.NewIntegerArray(intByteRange...)
	}

	if s.References != nil {
		refs := make(types.Array, len(s.References))
		for i, ref := range s.References {
			refs[i] = ref.ToPdfDict()
		}

		dict["Reference"] = refs
	}

	if s.Changes != nil {
		dict["Changes"] = s.Changes.ToPdfArr()
	}

	if s.Name != "" {
		dict["Name"] = types.StringLiteral(s.Name)
	}

	if !s.Time.IsZero() {
		dict["M"] = types.StringLiteral(types.DateString(s.Time))
	}

	if s.Location != "" {
		dict["Location"] = types.StringLiteral(s.Location)
	}

	if s.Reason != "" {
		dict["Reason"] = types.StringLiteral(s.Reason)
	}

	if s.ContactInfo != "" {
		dict["ContactInfo"] = types.StringLiteral(s.ContactInfo)
	}

	if s.HandlerVersion != nil {
		dict["R"] = types.Integer(*s.HandlerVersion)
	}

	if s.FormatVersion != 0 {
		dict["V"] = types.Integer(s.FormatVersion)
	}

	if s.PropBuild != nil {
		dict["Prop_Build"] = s.PropBuild
	}

	if s.PropAuthTime != nil {
		dict["Prop_AuthTime"] = types.Integer(*s.PropAuthTime)
	}

	if s.PropAuthType != "" {
		dict["Prop_AuthType"] = types.Name(s.PropAuthType)
	}

	return dict
}

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
