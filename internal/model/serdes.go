package model

import (
	"fmt"
)

//goland:noinspection GoMixedReceiverTypes
func (st SignType) String() string {
	switch st {
	case SignTypeCertification:
		return "certification"
	case SignTypeApproval:
		return "approval"
	}

	panic(fmt.Sprintf("invalid SignType enum value %d", st))
}

//goland:noinspection GoMixedReceiverTypes
func (st SignType) MarshalText() ([]byte, error) {
	return []byte(st.String()), nil
}

//goland:noinspection GoMixedReceiverTypes
func (st *SignType) UnmarshalText(text []byte) error {
	str := string(text)

	switch str {
	case "certification":
		*st = SignTypeCertification
		return nil
	case "approval":
		*st = SignTypeApproval
		return nil
	default:
		return fmt.Errorf("invalid SignType enum value %s", str)
	}
}

//goland:noinspection GoMixedReceiverTypes
func (dm DocMdp) String() string {
	switch dm {
	case DocMdpNoChanges:
		return "no-changes"
	case DocMdpFormSign:
		return "form-sign"
	case DocMdpAnnotFormSign:
		return "annot-form-sign"
	}

	panic(fmt.Sprintf("invalid DocMdp enum value \"%d\"", dm))
}

//goland:noinspection GoMixedReceiverTypes
func (dm DocMdp) MarshalText() ([]byte, error) {
	return []byte(dm.String()), nil
}

//goland:noinspection GoMixedReceiverTypes
func (dm *DocMdp) UnmarshalText(text []byte) error {
	str := string(text)

	switch str {
	case "no-changes":
		*dm = DocMdpNoChanges
		return nil
	case "form-sign":
		*dm = DocMdpFormSign
		return nil
	case "annot-form-sign":
		*dm = DocMdpAnnotFormSign
		return nil
	default:
		return fmt.Errorf("invalid DocMdp enum value \"%s\"", str)
	}
}
