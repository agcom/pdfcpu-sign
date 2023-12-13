package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agcom/pdfcpu-sign/internal/model"
	"github.com/go-chi/chi/v5"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
)

func Run() {
	r := chi.NewRouter()

	r.Post("/v1/sign", postSign)

	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: h2c.NewHandler(r, &http2.Server{}),
	}

	go func() {
		slog.Info("The HTTP server initialized.", "address", server.Addr)
	}()

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("The HTTP server closed unexpectedly.", "error", err)
	} else {
		slog.Info("The HTTP server was closed.", "error", err)
	}
}

func postSign(w http.ResponseWriter, r *http.Request) {
	inFile, signInfo, err, status := postSignRequestBodyExtract(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	defer func() {
		err := inFile.Close()
		if err != nil {
			slog.Warn("Closing a temporary file assigned to an input PDF failed.", "path", inFile.Name(), "error", err)
		}

		err = os.Remove(inFile.Name())
		if err != nil {
			slog.Error("Removing a temporary file assigned to an input PDF failed.", "path", inFile.Name(), "error", err)
		}
	}()

	// Make sure it is a PDF file.
	err = pdfcpu.ValidateFile(inFile.Name(), nil)
	if err != nil {
		http.Error(w, "Invalid PDF file.", http.StatusBadRequest)
		return
	}

	// Create a temporary file for the output signed PDF.
	outFile, err := os.CreateTemp("", "sign-server-output-*.pdf")
	if err != nil {
		slog.ErrorContext(r.Context(), "Creating a temporary file for an output PDF failed.", "error", err)
		http.Error(w, "Something went wrong on our side!", http.StatusInternalServerError)
		return
	}
	defer func() {
		err := outFile.Close()
		if err != nil {
			slog.Warn("Closing a temporary file assigned to an output PDF failed.", "path", outFile.Name(), "error", err)
		}

		err = os.Remove(outFile.Name())
		if err != nil {
			slog.Error("Removing a temporary file assigned to an output PDF failed.", "path", outFile.Name(), "error", err)
		}
	}()

	// Sign the PDF

	if r.Context().Err() != nil {
		return // Client closed the connection.
	}

	err = pdfSigner.SignModel(inFile.Name(), outFile.Name(), signInfo)
	if err != nil {
		http.Error(w, "Something went wrong on our side.", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "Signing a PDF file failed.", "error", err)
		return
	}

	// Return the output temporary file
	_, err = io.Copy(w, outFile)
	if err != nil {
		http.Error(w, "Something went wrong on our side.", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "Writing a signed PDF failed.", "error", err)
		return
	}
}

//goland:noinspection GoErrorStringFormat
func postSignRequestBodyExtract(r *http.Request) (*os.File, *model.SignInfo, error, int) {
	// Check the content type.
	mimeType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("Bad content-type header."), http.StatusBadRequest
	}
	if mimeType != "multipart/mixed" {
		return nil, nil, fmt.Errorf("Content type must be multipart/mixed, but was %s.", mimeType), http.StatusBadRequest
	}

	mpr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, fmt.Errorf("Bad multipart request."), http.StatusBadRequest
	}

	ok := false
	var signInfo *model.SignInfo = nil
	var inFile *os.File = nil
	defer func() {
		if !ok && inFile != nil {
			rmTmpFile(inFile)
		}
	}()

	var status int

	part, err := mpr.NextPart()
	if err != nil {
		return nil, nil, fmt.Errorf("Bad multipart request; failed to read the first part."), http.StatusBadRequest
	}

	partMimeType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	switch partMimeType {
	case "application/json":
		signInfo, err, status = postSignExtractJsonPart(part)
		if err != nil {
			return nil, nil, err, status
		}
	case "application/pdf":
		inFile, err, status = postSignExtractPdfPart(part)
		if err != nil {
			return nil, nil, err, status
		}
	default:
		return nil, nil, fmt.Errorf(
			`Unexpected content-type "%s" for the first part; expected either "application/json" or "application/pdf".`,
			partMimeType,
		), http.StatusBadRequest
	}

	part, err = mpr.NextPart()
	if err != nil {
		return nil, nil, fmt.Errorf("Bad multipart request; failed to read the second part."), http.StatusBadRequest
	}

	partMimeType, _, err = mime.ParseMediaType(part.Header.Get("Content-Type"))
	switch partMimeType {
	case "application/json":
		if signInfo != nil {
			return nil, nil,
				fmt.Errorf("Unexpected JSON second part; the first part was already JSON; expected PDF."),
				http.StatusBadRequest
		}
		signInfo, err, status = postSignExtractJsonPart(part)
		if err != nil {
			return nil, nil, err, status
		}
	case "application/pdf":
		if inFile != nil {
			return nil, nil,
				fmt.Errorf("Unexpected PDF second part; the first part was already PDF; expected JSON."),
				http.StatusBadRequest
		}
		inFile, err, status = postSignExtractPdfPart(part)
		if err != nil {
			return nil, nil, err, status
		}
	default:
		if signInfo == nil {
			return nil, nil,
				fmt.Errorf(
					`Unexpected content-type "%s" for the second part; expected "application/json".`,
					partMimeType,
				), http.StatusBadRequest
		} else {
			return nil, nil,
				fmt.Errorf(
					`Unexpected content-type "%s" for the second part; expected "application/pdf".`,
					partMimeType,
				), http.StatusBadRequest
		}
	}

	if _, err = mpr.NextPart(); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("Bad multipart request; too many parts, expected 2 only."), http.StatusBadRequest
	}

	ok = true

	return inFile, signInfo, nil, 0
}

//goland:noinspection GoErrorStringFormat
func postSignExtractJsonPart(part *multipart.Part) (*model.SignInfo, error, int) {
	// TODO: honor the charset in the content-type header params.
	jsonBytes, err := io.ReadAll(part)
	if err != nil {
		return nil, fmt.Errorf("Reading the JSON part's bytes failed; %w", err), http.StatusBadRequest
	}

	var signInfo model.SignInfo
	err = json.Unmarshal(jsonBytes, &signInfo)
	if err != nil {
		return nil, fmt.Errorf("Unmarshaling the JSON part failed; %w", err), http.StatusBadRequest
	}

	return &signInfo, nil, 0
}

//goland:noinspection GoErrorStringFormat
func postSignExtractPdfPart(part *multipart.Part) (*os.File, error, int) {
	// Flush the body (supposedly of type PDF) into a temporary file.
	inFile, err := os.CreateTemp("", "sign-server-input-*.pdf")
	if err != nil {
		slog.Error("Creating a temporary file for an input PDF failed.", "error", err)
		return nil, fmt.Errorf("Something went wrong on our side!"), http.StatusInternalServerError
	}

	ok := false

	defer func() {
		if !ok {
			rmTmpFile(inFile)
		}
	}()

	n, err := io.Copy(inFile, part)
	if err != nil {
		slog.Error("Writing to a temporary file or reading a request's body failed.", "inFilePath", inFile.Name(), "error", err, "bytesWritten", n)

		// Maybe the connection was closed by the client (in which case it may or may not receive this error message); thus the word "probably".
		return nil, fmt.Errorf("Something went wrong probably on our side."), http.StatusInternalServerError
	}

	ok = true
	return inFile, nil, 0
}

func rmTmpFile(tmp *os.File) {
	err := tmp.Close()
	if err != nil {
		slog.Warn("Closing a temporary file failed.", "path", tmp.Name(), "error", err)
	}

	err = os.Remove(tmp.Name())
	if err != nil {
		slog.Error("Removing a temporary file failed.", "path", tmp.Name(), "error", err)
	}
}
