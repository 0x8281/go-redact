package stdhttp

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/0x8281/go-redact/pkg/redact"
)

type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// Middleware creates a standard net/http middleware handler
func Middleware(engine *redact.Engine, opts ...Option) func(http.Handler) http.Handler {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || !cfg.shouldProcess(r.Header.Get("Content-Type")) {
				next.ServeHTTP(w, r)

				return
			}

			rawBytes, err := io.ReadAll(io.LimitReader(r.Body, cfg.maxBodyBytes))
			_ = r.Body.Close()
			if err != nil {
				cfg.errorHandler(w, r, err)

				return
			}

			if len(rawBytes) == 0 {
				r.Body = io.NopCloser(bytes.NewReader(nil))
				next.ServeHTTP(w, r)

				return
			}

			result, err := engine.Mask(r.Context(), string(rawBytes))
			if err != nil {
				cfg.errorHandler(w, r, err)

				return
			}

			maskedBytes := []byte(result.Text)
			r.Body = io.NopCloser(bytes.NewReader(maskedBytes))
			r.ContentLength = int64(len(maskedBytes))
			r.Header.Set("Content-Length", strconv.Itoa(len(maskedBytes)))
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(maskedBytes)), nil
			}

			r = r.WithContext(WithResult(r.Context(), result))

			if !cfg.autoDemask || len(result.Mapping) == 0 {
				next.ServeHTTP(w, r)

				return
			}

			rec := &responseRecorder{
				ResponseWriter: w,
				body:           &bytes.Buffer{},
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			outText := rec.body.String()
			restoredText := redact.Demask(outText, result.Mapping)

			if w.Header().Get("Content-Length") != "" {
				w.Header().Set("Content-Length", strconv.Itoa(len(restoredText)))
			}
			w.WriteHeader(rec.statusCode)
			_, _ = io.WriteString(w, restoredText)
		})
	}
}
