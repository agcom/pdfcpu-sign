package main

import (
	"log"
	"log/slog"

	"github.com/agcom/pdfcpu-sign/cmds/api/internal/http"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/pkcs11"
)

func main() {
	defer func() {
		slog.Info("Main Goroutine exiting.")
	}()

	defer func() {
		crypto11Ctx, err := pkcs11.GetCrypt11Ctx()
		if err != nil {
			slog.Warn("Getting the crypto11 context in order to close it failed.", "error", err)
			return
		}

		err = crypto11Ctx.Close()
		if err != nil {
			slog.Error("Closing the crypto11 context failed.", "error", err)
		}
	}()

	err := http.InitPdfSigner()
	if err != nil {
		log.Panicln(err)
	}

	http.Run()
}
