package model

import (
	"fmt"
	pdfsign "github.com/digitorus/pdfsign/sign"
)

func (si *SignInfo) ToDigitorusModel() *pdfsign.SignDataSignature {
	return &pdfsign.SignDataSignature{
		CertType:   si.Type.ToDigitorusModel(),
		DocMDPPerm: si.DocMdp.ToDigitorusModel(),
		Info: pdfsign.SignDataSignatureInfo{
			Name:        si.SignerInfo.Name,
			Location:    si.SignerInfo.Location,
			Reason:      si.SignerInfo.Reason,
			ContactInfo: si.SignerInfo.ContactInfo,
			Date:        si.SignerInfo.Date,
		},
	}
}

//goland:noinspection GoMixedReceiverTypes
func (st SignType) ToDigitorusModel() uint {
	switch st {
	case SignTypeCertification:
		return pdfsign.CertificationSignature
	case SignTypeApproval:
		return pdfsign.ApprovalSignature
	}

	panic(fmt.Sprintf("invalid SignType enum value %d", st))
}

//goland:noinspection GoMixedReceiverTypes
func (dm DocMdp) ToDigitorusModel() uint {
	switch dm {
	case DocMdpNoChanges:
		return pdfsign.DoNotAllowAnyChangesPerms
	case DocMdpFormSign:
		return pdfsign.AllowFillingExistingFormFieldsAndSignaturesPerms
	case DocMdpAnnotFormSign:
		return pdfsign.AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
	}

	panic(fmt.Sprintf("invalid DocMdp enum value %d", dm))
}
