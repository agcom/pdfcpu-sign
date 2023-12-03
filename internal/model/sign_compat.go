package model

import (
	"fmt"
	pdfsign "github.com/digitorus/pdfsign/sign"
)

func (si *SignInfo) ToOldModel() *pdfsign.SignDataSignature {
	return &pdfsign.SignDataSignature{
		CertType:   si.Type.ToOldModel(),
		DocMDPPerm: si.DocMdp.ToOldModel(),
		Info: pdfsign.SignDataSignatureInfo{
			Name:        si.SignerInfo.Name,
			Location:    si.SignerInfo.Location,
			Reason:      si.SignerInfo.Reason,
			ContactInfo: si.SignerInfo.ContactInfo,
			Date:        si.SignerInfo.Date,
		},
	}
}

func (st SignType) ToOldModel() uint {
	switch st {
	case SignTypeCertification:
		return pdfsign.CertificationSignature
	case SignTypeApproval:
		return pdfsign.ApprovalSignature
	}

	panic(fmt.Sprintf("invalid SignType enum value %d", st))
}

func (dm DocMdp) ToOldModel() uint {
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
