package pdfcpusign

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// strPdfArrElem is useful for encoding elements of a byte range array (in a signature dictionary);
// for example, [%10d %10d %10d] in which each element is a 10-width integer.
type strPdfArrElem string

func (s strPdfArrElem) String() string {
	return string(s)
}

func (s strPdfArrElem) Clone() types.Object {
	return s
}

func (s strPdfArrElem) PDFString() string {
	return string(s)
}

func rndSigFieldNameTrail() (string, error) {
	rndBytes := make([]byte, 3) // 3 bytes lead to 24 bits which lead to 4 base64 characters.
	_, err := rand.Read(rndBytes)
	if err != nil {
		return "", fmt.Errorf("failed to fetch some tiny bits of crypto random; %w", err)
	}
	return base64.URLEncoding.EncodeToString(rndBytes), nil
}

var contentsRegex = regexp.MustCompile(`/Contents\s*(?P<hex><.*?>)`)

// findContentsOffset returns the start and end offsets (relative to the given incBytes) of the hex capturing group in the contentsRegex regex.
func findContentsOffset(incBytes []byte) [2]int {
	subMatchesIndexes := contentsRegex.FindSubmatchIndex(incBytes)
	if subMatchesIndexes == nil {
		panic("no /Contents<...> found")
	}

	hexSubExpIndex := contentsRegex.SubexpIndex("hex")
	hexSubMatchOffset := subMatchesIndexes[2*hexSubExpIndex : 2*hexSubExpIndex+2]

	return [2]int{hexSubMatchOffset[0], hexSubMatchOffset[1]}
}

func hasEol(in io.ReadSeeker) (bool, error) {
	_, err := in.Seek(-1, io.SeekEnd)
	if err != nil {
		return false, fmt.Errorf("seek to last byte: %w", err)
	}

	lastBytes := [1]byte{}
	_, err = in.Read(lastBytes[:])
	if err != nil {
		return false, fmt.Errorf("read last byte: %w", err)
	}

	switch lastBytes[0] {
	case '\n', '\r':
		return true, nil
	default:
		return false, nil
	}
}

func ensureEol(in io.ReadSeeker, out io.Writer) error {
	hasEolV, err := hasEol(in)
	if err != nil {
		return err
	}

	if !hasEolV {
		_, err = out.Write([]byte{'\n'})
		if err != nil {
			return fmt.Errorf("write eol: %w", err)
		}
	}

	return nil
}
