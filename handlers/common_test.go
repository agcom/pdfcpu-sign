package handlers

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/agcom/pdfcpu-sign/testutils"
	"log/slog"
	"os"
	"path"
	"testing"
)

var pvKey crypto.PrivateKey
var pubKey crypto.PublicKey
var cert *x509.Certificate

func init() {
	pvKey, pubKey, cert = testutils.GenKert()
}

const samplesDirRel = "./../_samples/"

var samples []string

func init() {
	entries, err := os.ReadDir(samplesDirRel)
	if err != nil {
		panic(fmt.Errorf("failed to list files in the samples directory; %w", err))
	}

	samples = make([]string, len(entries))

	for i, entry := range entries {
		samples[i] = path.Join(samplesDirRel, entry.Name())
	}
}

var tmpDir string

func TestMain(m *testing.M) {
	var err error
	tmpDir, err = os.MkdirTemp("", "agcom-pdfcpu-sign-pdfcpusign-tests-*")
	if err != nil {
		panic(fmt.Errorf("failed to create a temporary directory; %w", err))
	}

	exitCode := m.Run()

	err = os.RemoveAll(tmpDir)
	if err != nil {
		slog.Error("Removing the common temporary directory failed.", "path", tmpDir, "error", err)
	}

	os.Exit(exitCode)
}
