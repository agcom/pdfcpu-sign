package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agcom/pdfcpu-sign/cmds/api/internal/signpdf"
	"github.com/go-chi/chi/v5"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"log"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
)

func Run() {
	r := chi.NewRouter()

	r.Post("/v1/sign", postSign)

	port, err := getHttpPortConf()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Panicln(err)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: h2c.NewHandler(r, &http2.Server{}),
	}

	go func() {
		slog.Info("The HTTP server initialized.", "address", server.Addr)
	}()

	err = server.ListenAndServe()
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
			slog.Warn("Closing the temporary file assigned to the output PDF failed.", "path", outFile.Name(), "error", err)
		}

		err = os.Remove(outFile.Name())
		if err != nil {
			slog.Error("Removing the temporary file assigned to the output PDF failed.", "path", outFile.Name(), "error", err)
		}
	}()

	// Sign the PDF

	if r.Context().Err() != nil {
		return // Client closed the connection.
	}

	err = pdfSigner.Sign(inFile, outFile, signInfo)
	if err != nil {
		http.Error(w, "Something went wrong on our side.", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "Signing a PDF file failed.", "error", err)
		return
	}

	// Return the output temporary file
	_, err = outFile.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "Something went wrong on our side.", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "Seeking the signed PDF temporary output file failed.", "error", err)
		return
	}

	_, err = io.Copy(w, outFile)
	if err != nil {
		http.Error(w, "Something went wrong on our side.", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "Writing a signed PDF failed.", "error", err)
		return
	}
}

//goland:noinspection GoErrorStringFormat
func postSignRequestBodyExtract(r *http.Request) (*os.File, *signpdf.SignInfo, error, int) {
	// Check the content type.
	mimeType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("Bad content-type header."), http.StatusBadRequest
	}
	if mimeType != "multipart/form-data" {
		return nil, nil, fmt.Errorf("Content type must be multipart/form-data, but was %s.", mimeType), http.StatusBadRequest
	}

	mpr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, fmt.Errorf("Bad multipart request; %w.", err), http.StatusBadRequest
	}

	ok := false
	var signInfo *signpdf.SignInfo = nil
	var pdfFile *os.File = nil
	defer func() {
		if !ok && pdfFile != nil {
			rmTmpFile(pdfFile)
		}
	}()

	for {
		part, err := mpr.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return nil, nil, fmt.Errorf("Bad multipart request; %w.", err), http.StatusBadRequest
			}
		}

		contentDispos, contentDisposParams, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			return nil, nil, fmt.Errorf("Bad content-disposition header of a part; %w.", err), http.StatusBadRequest
		}
		if contentDispos != "form-data" {
			return nil, nil, fmt.Errorf("Invalid content-disposition header of a part; not form-data."), http.StatusBadRequest
		}

		name := contentDisposParams["name"]
		if name == "" {
			return nil, nil, fmt.Errorf("No name provided for a form field."), http.StatusBadRequest
		}

		switch name {
		case "sign-info":
			if signInfo != nil {
				return nil, nil, fmt.Errorf("Unexpected multiple values for the sign-info form field."), http.StatusBadRequest
			}

			var status int
			signInfo, err, status = postSignExtractSignInfo(part)
			if err != nil {
				return nil, nil, fmt.Errorf("Something wrong with a sign-info field; %w.", err), status
			}

			break
		case "pdf-file":
			if pdfFile != nil {
				return nil, nil, fmt.Errorf("Unexpected multiple values for the pdf-file form field."), http.StatusBadRequest
			}

			fileName := contentDisposParams["filename"]
			if fileName == "" {
				return nil, nil, fmt.Errorf("Expected a file in the pdf-file form field (set the content-disposition header param filename)."), http.StatusBadRequest
			}

			var status int
			pdfFile, err, status = postSignExtractPdfFile(part, fileName)
			if err != nil {
				return nil, nil, fmt.Errorf("Something wront with a pdf-file form field; %w.", err), status
			}
			break
		default:
			return nil, nil, fmt.Errorf("Unexpected form field %s.", name), http.StatusBadRequest
		}
	}

	if signInfo == nil {
		return nil, nil, fmt.Errorf("Expected a sign-info form field, but got none."), http.StatusBadRequest
	}

	if pdfFile == nil {
		return nil, nil, fmt.Errorf("Expected a pdf-file form field, but got none."), http.StatusBadRequest
	}

	ok = true

	return pdfFile, signInfo, nil, 0
}

//goland:noinspection GoErrorStringFormat
func postSignExtractSignInfo(part *multipart.Part) (*signpdf.SignInfo, error, int) {
	partMimeType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("bad content-type header; %w", err), http.StatusBadRequest
	}

	if partMimeType != "application/json" {
		return nil, fmt.Errorf("expected application/json as the content-type, but got %q", partMimeType), http.StatusBadRequest
	}

	// TODO (minor improvement): honor the charset in the content-type header params.
	jsonBytes, err := io.ReadAll(part)
	if err != nil {
		return nil, fmt.Errorf("reading the JSON part's bytes failed; %w", err), http.StatusBadRequest
	}

	var signInfo signpdf.SignInfo
	err = json.Unmarshal(jsonBytes, &signInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling the JSON part failed; %w", err), http.StatusBadRequest
	}

	return &signInfo, nil, 0
}

//goland:noinspection GoErrorStringFormat
func postSignExtractPdfFile(part *multipart.Part, filename string) (*os.File, error, int) {
	mimetype, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("bad content-type header; %w", err), http.StatusBadRequest
	}

	if mimetype != "application/pdf" {
		return nil, fmt.Errorf("expected application/pdf as the content-type, but got %q", mimetype), http.StatusBadRequest
	}

	// Flush the body (supposedly of type PDF) into a temporary file.
	// TODO: use a common temporary directory for the application.
	inFile, err := os.CreateTemp("", "sign-server-input-*.pdf")
	if err != nil {
		slog.Error("Creating a temporary file for an input PDF failed.", "error", err)
		return nil, fmt.Errorf("something went wrong on our side"), http.StatusInternalServerError
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
		return nil, fmt.Errorf("something went wrong probably on our side"), http.StatusInternalServerError
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
