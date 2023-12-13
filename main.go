package main

import (
	"github.com/agcom/pdfcpu-sign/internal/http"
	"github.com/agcom/pdfcpu-sign/internal/p11"
	"log"
	"log/slog"
)

func main() {
	err := p11.InitCrypto11Ctx()
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		err := p11.C11Ctx.Close()
		if err != nil {
			slog.Error("Closing the crypto11 context failed.", "error", err)
		}
	}()

	err = p11.InitKert()
	if err != nil {
		log.Panicln(err)
	}

	err = http.InitPdfSigner()
	if err != nil {
		log.Panicln(err)
	}

	http.Run()

	slog.Warn("Main Goroutine exited.")
}
