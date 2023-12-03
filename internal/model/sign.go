// TODO: promote to a decoupled package?
package model

import (
	"time"
)

// SignType defines the signature type to use.
type SignType int

const (
	// SignTypeCertification is a signature type that can be applied once to a PDF document (it must be the first signature),
	// and is always associated with the DocMDP field.
	SignTypeCertification SignType = iota

	// SignTypeApproval is a signature type that can be applied multiple times to a PDF document.
	SignTypeApproval
)

// DocMdp (DocMDP) stands for Document Modification Detection and Prevention, post-signing.
type DocMdp int

const (
	// DocMdpNoChanges allows no changes to the document after signing.
	DocMdpNoChanges DocMdp = iota

	// DocMdpFormSign allows form fill-in and adding additional digital signatures after signing.
	DocMdpFormSign

	// DocMdpAnnotFormSign allows adding annotations (for example commenting), form fill-in, and adding additional digital signatures post-signing.
	DocMdpAnnotFormSign
)

// SignerInfo is only designed to be used in unmarshal positions (and not marshal positions) regarding ser/deserialization.
type SignerInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

// SignInfo is only designed to be used in unmarshal positions (and not marshal positions) regarding ser/deserialization.
type SignInfo struct {
	Type       SignType
	DocMdp     DocMdp
	SignerInfo SignerInfo
}
