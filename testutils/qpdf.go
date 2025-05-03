package testutils

import (
	"errors"
	"fmt"
	"os/exec"
)

func QpdfCheck(pdfPath string) (string, error) {
	// TODO: use the qpdf C library instead of relying on the command line.
	_, err := exec.LookPath("qpdf")
	if err != nil {
		if !errors.Is(err, exec.ErrDot) {
			return "", fmt.Errorf("the qpdf command is not available: %w", err)
		}
	}

	cmd := exec.Command("qpdf", "--check", pdfPath)
	outBytes, err := cmd.CombinedOutput()

	if err != nil {
		return string(outBytes), fmt.Errorf("qpdf check failed; %w", err)
	} else {
		return string(outBytes), nil
	}
}
