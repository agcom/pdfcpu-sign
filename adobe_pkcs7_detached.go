package pdfcpu_sign

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/smallstep/pkcs7"
)

type adobePkcs7DetachedSigHandler struct {
	pvKey crypto.PrivateKey
	cert  *x509.Certificate

	// certParents is  trust chain for the cert
	// (should not contain the cert itself as the first element).
	// Can be empty (for example when the cert is self-signed or is from a trusted CA).
	certParents []*x509.Certificate

	digestAlgOid asn1.ObjectIdentifier

	// isCtxOrigin if true it means to read the original PDF bytes by writing the context, otherwise, by reading the context's source (a read seeker).
	// The user should be aware of this, because it changes the write procedure after signing the context (if it is true, the user should write the context before signing it, because the context is not aware of the increments).
	// TODO: true value enforces multiple same writes; one when signing, and the other before signing; optimize the architecture.
	// TODO: remove this functionality (or polish its related documentation for consistency)?
	isCtxOrigin bool

	// TODO: timestamp & revocation information
}

func NewAdobePkcs7DetachedSigHandler(
	pvKey crypto.PrivateKey,
	cert *x509.Certificate,
	certParents []*x509.Certificate,
	digestAlg crypto.Hash,
) SigHandler {
	return &adobePkcs7DetachedSigHandler{
		pvKey:        pvKey,
		cert:         cert,
		certParents:  certParents,
		digestAlgOid: cryptoDigestAlgToPkcs7DigestAlgOid(digestAlg),
		isCtxOrigin:  false, // The pdfcpu library is not ready for this functionality.
	}
}

func (h *adobePkcs7DetachedSigHandler) Sign(ctx *model.Context, sig *Sig) error {
	var err error

	// Preserve the original PDF bytes before altering the non-increment-aware context.
	var originPdfBytes []byte
	if h.isCtxOrigin {
		originPdfBytes, err = writeAll(ctx)
		if err != nil {
			return fmt.Errorf("failed to write a PDF context; %w", err)
		}
	} else {
		_, err = ctx.Read.RS.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek a PDF reader; %w", err)
		}
		originPdfBytes = make([]byte, ctx.Read.FileSize)
		_, err = io.ReadFull(ctx.Read.RS, originPdfBytes)
		if err != nil {
			return fmt.Errorf("failed to read a PDF file bytes; %w", err)
		}
	}
	originPdfLen := int64(len(originPdfBytes))

	// Add an EOL marker if it does not have one.
	switch originPdfBytes[originPdfLen-1] {
	case '\n', '\r':
		break
	default:
		originPdfBytes = append(originPdfBytes, '\n')
	}

	err = h.initSig(sig)
	if err != nil {
		return fmt.Errorf("failed to initialize a signature; %w", err)
	}

	sigField := SigField{}
	err, sigDict := h.initSigField(ctx, sig, &sigField)
	if err != nil {
		return fmt.Errorf("failed to initialize a signature field; %w", err)
	}

	// Insert the signature field (which includes the signature).
	sigFieldDict := sigField.ToPdfDict()
	sigFieldRef, err := ctx.IndRefForNewObject(sigFieldDict)
	if err != nil {
		return fmt.Errorf("failed to insert a signature field dictionary; %w", err)
	}
	ctx.Write.IncrementWithObjNr(sigFieldRef.ObjectNumber.Value())

	// Update the annotations entry in the page dictionary referenced by the signature field.
	if sigField.Page != nil {
		pageDict, err := ctx.DereferenceDict(*sigField.Page)
		if err != nil {
			return fmt.Errorf("failed to dereference a page indirect reference of a PDF; %w", err)
		}

		annotsObj := pageDict["Annots"]
		if annotsObj == nil {
			pageDict["Annots"] = types.Array{*sigFieldRef}
			ctx.Write.IncrementWithObjNr(sigField.Page.ObjectNumber.Value())
		} else if annotsArr, ok := annotsObj.(types.Array); ok {
			pageDict["Annots"] = append(annotsArr, *sigFieldRef)
			ctx.Write.IncrementWithObjNr(sigField.Page.ObjectNumber.Value())
		} else if annotsRef, ok := annotsObj.(types.IndirectRef); ok {
			annotsTableEntry, _ := ctx.FindTableEntryForIndRef(&annotsRef)
			annotsArr, ok := annotsTableEntry.Object.(types.Array)
			if !ok {
				return fmt.Errorf("invalid annotations array: %v", annotsTableEntry.Object)
			}
			annotsTableEntry.Object = append(annotsArr, *sigFieldRef)
			ctx.Write.IncrementWithObjNr(annotsRef.ObjectNumber.Value())
		} else {
			return fmt.Errorf("invalid /Annots entry types: %v", annotsObj)
		}
	}

	catalogDict, err := ctx.Catalog()
	if err != nil {
		return fmt.Errorf("failed to read a PDF catalog dictionary; %w", err)
	}

	// If it is a certification signature, set the Catalog.Perms.DocMDP entry.
	if ok, _ := isCertSig(sig); ok {
		permsObj := catalogDict["Perms"]
		if permsObj == nil { // No perms dict; insert one and update the catalog.
			permsDict := types.NewDict()
			permsDict["DocMDP"] = *sigField.Value
			permsRef, err := ctx.IndRefForNewObject(permsDict)
			if err != nil {
				return fmt.Errorf("failed to insert a permissions dictionary; %w", err)
			}
			ctx.Write.IncrementWithObjNr(permsRef.ObjectNumber.Value())

			catalogDict["Perms"] = *permsRef
			ctx.Write.IncrementWithObjNr(ctx.Root.ObjectNumber.Value())
		} else if permsRef, ok := permsObj.(types.IndirectRef); ok { // The /Perms entry is an indirect object; just update the permissions dictionary.
			permsDict, err := ctx.DereferenceDict(permsRef)
			if err != nil {
				return fmt.Errorf("failed to dereference the permissions dictionary indirect reference; %w", err)
			}
			permsDict["DocMDP"] = *sigField.Value
			ctx.Write.IncrementWithObjNr(permsRef.ObjectNumber.Value())
		} else if permsDict, ok := permsObj.(types.Dict); ok { // The /Perms entry is a direct dictionary; insert it and update the catalog.
			permsDict["DocMDP"] = *sigField.Value
			permsRef, err := ctx.IndRefForNewObject(permsDict)
			if err != nil {
				return fmt.Errorf("failed to insert a permissions dictionary; %w", err)
			}
			ctx.Write.IncrementWithObjNr(permsRef.ObjectNumber.Value())

			catalogDict["Perms"] = *permsRef
			ctx.Write.IncrementWithObjNr(ctx.Root.ObjectNumber.Value())
		} else {
			return fmt.Errorf("invalid /Perms entry in the catalog, neither an indirect reference nor a dictionary: %v", permsObj)
		}
	}

	// Update the form dictionary.
	formObj := catalogDict["AcroForm"]
	if formObj == nil { // No form dictionary; insert one and update the catalog.
		formDict := types.NewDict()
		formDict["Fields"] = types.Array{*sigFieldRef}
		formDict["SigFlags"] = types.Integer(0b11) // TODO: model signature flags.

		formRef, err := ctx.IndRefForNewObject(formDict)
		if err != nil {
			return fmt.Errorf("failed to insert a form dictionary; %w", err)
		}
		ctx.Write.IncrementWithObjNr(formRef.ObjectNumber.Value())

		catalogDict["AcroForm"] = *formRef
		ctx.Write.IncrementWithObjNr(ctx.Root.ObjectNumber.Value())

		ctx.Form = formDict // Update the context, just in case.
	} else if formRef, ok := formObj.(types.IndirectRef); ok { // The /AcroForm entry is an indirect reference; just update the form dictionary.
		formDict, err := ctx.DereferenceDict(formRef)
		if err != nil {
			return fmt.Errorf("failed to dereference the form dictionary; %w", err)
		}

		formDict["Fields"] = append(formDict.ArrayEntry("Fields"), *sigFieldRef)
		formDict["SigFlags"] = types.Integer(0b11)
		ctx.Write.IncrementWithObjNr(formRef.ObjectNumber.Value())

		ctx.Form = formDict // Update the context, just in case.
	} else if formDict, ok := formObj.(types.Dict); ok { // The /AcroForm entry is a direct dictionary; insert it and update the catalog.
		formDict["Fields"] = append(formDict.ArrayEntry("Fields"), *sigFieldRef)
		formDict["SigFlags"] = types.Integer(0b11)

		formRef, err := ctx.IndRefForNewObject(formDict)
		if err != nil {
			return fmt.Errorf("failed to insert a form dictionary; %w", err)
		}
		ctx.Write.IncrementWithObjNr(formRef.ObjectNumber.Value())

		catalogDict["AcroForm"] = *formRef
		ctx.Write.IncrementWithObjNr(ctx.Root.ObjectNumber.Value())

		ctx.Form = formDict // Update the context, just in case.
	} else {
		return fmt.Errorf("invalid /AcroForm catalog entry, neither an indirect reference, nor a direct dictionary: %v", formObj)
	}

	// Update the context, just in case.
	ctx.SignatureExist = true
	ctx.AppendOnly = true

	// Test write the increment to find out the actual byte range.

	incBytes, err := writeInc(ctx, originPdfLen)
	if err != nil {
		return fmt.Errorf("failed to find out actual byte range of a signature contents; %w", err)
	}

	contentsOffset := findContentsOffset(incBytes)
	actualByteRange := [4]int64{
		sig.ByteRange[0], // Must be 0.
		originPdfLen + int64(contentsOffset[0]),
		originPdfLen + int64(contentsOffset[1]),
		int64(len(incBytes)) - int64(contentsOffset[1]),
	}

	sigDict["ByteRange"] = types.Array{
		types.Integer(actualByteRange[0]), // Must be 0.
		strPdfArrElem(fmt.Sprintf("%10d", actualByteRange[1])),
		strPdfArrElem(fmt.Sprintf("%10d", actualByteRange[2])),
		strPdfArrElem(fmt.Sprintf("%10d", actualByteRange[3])),
	}
	sig.ByteRange = actualByteRange[:] // Update the signature model, just in case.

	// Sign the actual data.

	dataBuf := bytes.NewBuffer(make([]byte, 0, actualByteRange[1]+actualByteRange[3]))
	_, _ = dataBuf.Write(originPdfBytes)

	incBytes, err = writeInc(ctx, originPdfLen)
	if err != nil {
		return fmt.Errorf("failed to sign the actual data of a PDF; %w", err)
	}
	_, _ = dataBuf.Write(incBytes[:actualByteRange[1]-originPdfLen])
	_, _ = dataBuf.Write(incBytes[actualByteRange[2]-originPdfLen:])

	marshaledSig, err := h.marshalSig(dataBuf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to marshal a signature; %w", err)
	}

	sigDict["Contents"] = types.NewHexLiteral(marshaledSig)
	sig.Contents = marshaledSig // Update the model, just in case.

	// Update the context for future increment writes.
	ctx.Write.Offset = originPdfLen
	ctx.Write.Increment = true

	return nil
}

func writeInc(ctx *model.Context, originOffset int64) ([]byte, error) {
	// Reset the write context on return.
	defer func(oldCtxWriter *bufio.Writer, oldInc bool, oldOffset int64) {
		ctx.Write.Writer = oldCtxWriter
		ctx.Write.Increment = oldInc
		ctx.Write.Offset = oldOffset
	}(ctx.Write.Writer, ctx.Write.Increment, ctx.Write.Offset)

	incBuf := bytes.NewBuffer(nil)

	ctx.Write.Increment = true
	ctx.Write.Offset = originOffset
	err := api.WriteIncrement(ctx, incBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to write a PDF incremental update; %w", err)
	}

	return incBuf.Bytes(), nil
}

func writeAll(ctx *model.Context) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, ctx.Read.FileSize))
	err := api.WriteContext(ctx, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write a pdfcpu context; %w", err)
	}

	return buf.Bytes(), nil
}

func (h *adobePkcs7DetachedSigHandler) initSig(sig *Sig) error {
	sig.Type = SigTypeSig
	sig.Filter = FilterAdobePpkLite
	sig.SubFilter = SubFilterAdobePkcs7Detached

	// These should not be set when using this signature handler.
	sig.Cert = nil
	sig.HandlerVersion = nil
	sig.FormatVersion = 0

	// TODO: does the added signature field should be counted in this (currently the following code does so)?
	if sig.Changes == nil {
		sig.Changes = &SigChanges{}
	}
	sig.Changes.FieldsAltered++
	sig.Changes.FieldsFilledIn++

	err := h.allocContents(sig)
	if err != nil {
		return err
	}

	// Byte range placeholder, having a constant length; to be later replace with the actual byte range, but preserving the same length.
	const pdfMaxByteOffset int64 = 9999999999
	sig.ByteRange = []int64{0, pdfMaxByteOffset, pdfMaxByteOffset, pdfMaxByteOffset}

	return nil
}

// initSigField initializes the given brand-new signature field.
// The function is not ready for initializing an already existing signature field.
// It mutates the given context by inserting the given signature dictionary and a signature field lock dictionary if it is a certification signature.
func (h *adobePkcs7DetachedSigHandler) initSigField(ctx *model.Context, sig *Sig, sigField *SigField) (error, types.Dict) {
	nameTrail, err := rndSigFieldNameTrail()
	if err != nil {
		return fmt.Errorf("failed to generate a random trailing string for a signature field partial name; %w", err), nil
	}

	sigField.PartialName = "Signature_" + nameTrail
	sigField.FieldFlags = FieldFlagRequired | FieldFlagReadOnly | FieldFlagNoExport

	sigDict := sig.ToPdfDict()
	sigRef, err := ctx.IndRefForNewObject(sigDict)
	if err != nil {
		return fmt.Errorf("failed to insert a signature dictionary; %w", err), nil
	}
	sigField.Value = sigRef
	ctx.Write.IncrementWithObjNr(sigRef.ObjectNumber.Value())

	// TODO: should we create a SigFieldLock and add the signature field itself to it if it is an approval signature?
	// If it is a certification signature, add the signature field lock dictionary.
	if ok, perm := isCertSig(sig); ok {
		sigFieldLock := SigFieldLock{
			Action: FieldMdpActionAll,
			Perm:   perm,
		}

		sigFieldLockRef, err := ctx.IndRefForNewObject(sigFieldLock.ToPdfDict())
		if err != nil {
			return fmt.Errorf("failed to insert a signature field lock dictionary object; %w", err), sigDict
		}
		ctx.Write.IncrementWithObjNr(sigFieldLockRef.ObjectNumber.Value())

		sigField.Lock = sigFieldLockRef
	}

	// Set the page entry in the signature field.
	firstPageRef, err := ctx.PageDictIndRef(1)
	if err != nil {
		return fmt.Errorf("failed to find the first page of a PDF; %w", err), sigDict
	}
	sigField.Page = firstPageRef

	return nil, sigDict
}

func (h *adobePkcs7DetachedSigHandler) marshalSig(data []byte) ([]byte, error) {
	pkcs7Sig, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to create a PKCS#7 signature container; %w", err)
	}

	pkcs7Sig.SetDigestAlgorithm(h.digestAlgOid)

	err = pkcs7Sig.AddSignerChain(h.cert, h.pvKey, h.certParents, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, fmt.Errorf("failed to add signature info (certificates and attributes) to a PKCS#7 signature container; %w", err)
	}

	pkcs7Sig.Detach()
	marshaledSig, err := pkcs7Sig.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal a PKCS#7 signature container; %w", err)
	}

	return marshaledSig, nil
}

// allocContents determines the size of the contents entry by signing a dummy data.
func (h *adobePkcs7DetachedSigHandler) allocContents(sig *Sig) error {
	dummyMarshaledSig, err := h.marshalSig([]byte("Dummy data..."))
	if err != nil {
		return fmt.Errorf("failed to determine the size of the contents entry in a signature by signing a dummy data; %w", err)
	}

	sig.Contents = make([]byte, len(dummyMarshaledSig))
	return nil
}

// isCertSig checks if the given signature is intended for certification,
// and if it is so, returns the associated permission.
func isCertSig(sig *Sig) (bool, DocMdpPerm) {
	for _, sigRef := range sig.References {
		if sigRef.TransformMethod == TransformMethodDocMdp {
			return true, sigRef.TransformParams.(*TransformParamsDocMdp).Perm
		}
	}

	return false, 0
}

func cryptoDigestAlgToPkcs7DigestAlgOid(cryptoDigestAlg crypto.Hash) asn1.ObjectIdentifier {
	switch cryptoDigestAlg {
	case crypto.SHA1:
		return pkcs7.OIDDigestAlgorithmSHA1
	case crypto.SHA256:
		return pkcs7.OIDDigestAlgorithmSHA256
	case crypto.SHA384:
		return pkcs7.OIDDigestAlgorithmSHA384
	case crypto.SHA512:
		return pkcs7.OIDDigestAlgorithmSHA512
	case crypto.SHA224:
		return pkcs7.OIDDigestAlgorithmSHA224

	// TODO: support DSA and ECDSA.

	default:
		panic("unsupported hash function")
	}
}
