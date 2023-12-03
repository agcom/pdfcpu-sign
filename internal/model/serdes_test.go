package model

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

var testSignInfo = SignInfo{
	Type:   SignTypeCertification,
	DocMdp: DocMdpNoChanges,
	SignerInfo: SignerInfo{
		Name:        "Alireza",
		Location:    "Earth",
		Reason:      "Sealing",
		ContactInfo: "example@example.com",
	},
}

var testSignInfoJsonStr = `{
	"type": "certification",
	"docMdp": "no-changes",
	"signerInfo": {
		"name": "Alireza",
		"location": "Earth",
		"reason": "Sealing",
		"contactInfo": "example@example.com"
	}
}`

func TestSignInfo_UnarshalJSON(t *testing.T) {
	var signInfo SignInfo
	err := json.Unmarshal([]byte(testSignInfoJsonStr), &signInfo)
	require.NoError(t, err)

	require.Equal(t, testSignInfo, signInfo)
}
