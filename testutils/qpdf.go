package testutils

import (
	"errors"
	"fmt"
	"os/exec"
)

func QpdfCheck(pdfPath string) (string, error) {
	// TODO: use the qpdf C library instead of relying on the command line.
	_, err := exec.LookPath("qpdf")
	if err != nil && !errors.Is(err, exec.ErrDot) {
		return "", fmt.Errorf("the qpdf command is not available: %w", err)
	}

	cmd := exec.Command("qpdf", "--check", pdfPath)

	outBytes, err := cmd.CombinedOutput()
	outStr := string(outBytes)

	if err != nil {
		return outStr, fmt.Errorf("qpdf check failed: %w", err)
	} else if cmd.ProcessState.ExitCode() != 0 {
		return outStr, fmt.Errorf("qpdf check exited with non-zero code %d", cmd.ProcessState.ExitCode())
	} else {
		return outStr, nil
	}
}
