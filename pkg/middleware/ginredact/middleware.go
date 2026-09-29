package ginredact

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/0x8281/go-redact/pkg/redact"
)

const ContextKey = "go-redact:result"

// Option configures Gin redaction middleware behavior
type Option func(*config)

type config struct {
	maxBodyBytes int64
	contentTypes []string
	autoDemask   bool
}

// WithMaxBodyBytes sets the maximum body read limit (default: 5MB)
func WithMaxBodyBytes(limit int64) Option {
	return func(c *config) {
		if limit > 0 {
			c.maxBodyBytes = limit
		}
	}
}

// WithContentTypes specifies allowable Content-Types for redaction
func WithContentTypes(types ...string) Option {
	return func(c *config) {
		c.contentTypes = types
	}
}

// WithAutoDemask enables automatic placeholder demasking on outgoing HTTP responses
func WithAutoDemask(enabled bool) Option {
	return func(c *config) {
		c.autoDemask = enabled
	}
}

func (c *config) shouldProcess(contentType string) bool {
	if len(c.contentTypes) == 0 {
		return true
	}

	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, ct := range c.contentTypes {
		if strings.ToLower(ct) == mediaType {
			return true
		}
	}

	return false
}

type bodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *bodyWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *bodyWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

// Middleware returns a Gin HandlerFunc that masks request payloads
func Middleware(engine *redact.Engine, opts ...Option) gin.HandlerFunc {
	cfg := &config{
		maxBodyBytes: 5 * 1024 * 1024,
		contentTypes: []string{"application/json", "text/plain", "application/x-www-form-urlencoded"},
		autoDemask:   false,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return func(c *gin.Context) {
		if c.Request.Body == nil || !cfg.shouldProcess(c.ContentType()) {
			c.Next()

			return
		}

		rawBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, cfg.maxBodyBytes))
		_ = c.Request.Body.Close()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to read body"})

			return
		}

		if len(rawBytes) == 0 {
			c.Request.Body = io.NopCloser(bytes.NewReader(nil))
			c.Next()

			return
		}

		result, err := engine.Mask(c.Request.Context(), string(rawBytes))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to redact payload"})

			return
		}

		maskedBytes := []byte(result.Text)
		c.Request.Body = io.NopCloser(bytes.NewReader(maskedBytes))
		c.Request.ContentLength = int64(len(maskedBytes))
		c.Request.Header.Set("Content-Length", strconv.Itoa(len(maskedBytes)))
		c.Request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(maskedBytes)), nil
		}

		c.Set(ContextKey, result)

		if !cfg.autoDemask || len(result.Mapping) == 0 {
			c.Next()

			return
		}

		bw := &bodyWriter{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
		}
		c.Writer = bw

		c.Next()

		originalOutput := bw.body.String()
		restoredOutput := redact.Demask(originalOutput, result.Mapping)

		c.Header("Content-Length", strconv.Itoa(len(restoredOutput)))
		_, _ = bw.ResponseWriter.WriteString(restoredOutput)
	}
}

// GetResult retrieves the redaction Result from Gin Context
func GetResult(c *gin.Context) (redact.Result, bool) {
	val, exists := c.Get(ContextKey)
	if !exists {
		return redact.Result{}, false
	}

	res, ok := val.(redact.Result)

	return res, ok
}
