package signpdf

import (
	"time"
)

// SignType defines the signature type to use.
type SignType string

const (
	// SignTypeCert is a signature type that can be applied once to a PDF document (it must be the first signature),
	// and is always to be associated with the DocMDP field.
	SignTypeCert SignType = "certification"

	// SignTypeApproval is a signature type that can be applied multiple times to a PDF document.
	SignTypeApproval = "approval"
)

// DocMdp (DocMDP) stands for Document Modification Detection and Prevention; only to be used beside SignTypeCert.
type DocMdp string

const (
	// DocMdpNoChanges allows no changes to the document after signing.
	DocMdpNoChanges DocMdp = "no-changes"

	// DocMdpFormSign allows form fill-in and adding additional digital signatures after signing.
	DocMdpFormSign = "form-sign"

	// DocMdpFormSignAnnot allows form fill-in, adding additional digital signatures, and adding annotations (for example commenting), post-signing.
	DocMdpFormSignAnnot = "form-sign-annot"
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
	DocMdp     DocMdp
	SignerInfo *SignerInfo
}
