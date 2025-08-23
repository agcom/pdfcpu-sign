# PDFCPU Sign

A Go-native PDF signing library, on top of [pdfcpu](https://github.com/pdfcpu/pdfcpu).

## Simple Usage Example

Currently, the only implemented signature handler is Adobe PKCS#7 detached (CMS) which is by far the most widely used one.

```go
package main

import (
	"crypto"
	"log"
	"time"

	pdfcpusign "github.com/agcom/pdfcpu-sign"
	"github.com/agcom/pdfcpu-sign/testutils"
)

func main() {
	pvKey, _, cert := testutils.GenKert()
	sigHandler := pdfcpusign.NewAdobePkcs7DetachedSigHandler(pvKey, cert, nil, crypto.SHA256)

	err := pdfcpusign.SignFile(
		sigHandler,
		"./_samples/minimal.pdf", "./_samples/minimal-signed.pdf",
		(&pdfcpusign.SignInfo{
			Type:   pdfcpusign.SignTypeCert,
			DocMdp: pdfcpusign.DocMdpPermNoChanges,
			SignerInfo: &pdfcpusign.SignerInfo{
				Name:        "Alireza",
				Location:    "Earth",
				Reason:      "Test",
				ContactInfo: "example@example.com",
				Time:        time.Now(),
			},
		}).ToSig(),
	)
	if err != nil {
		log.Fatalf("Sign PDF failed: %s.\n", err)
	}
}

```

## API Application

There is an API application at [/cmds/api](./cmds/api) that utilizes keys over a [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) interface.
