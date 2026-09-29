package stdhttp

import (
	"net/http"
	"strings"
)

// Option configures the HTTP redaction middleware behavior
type Option func(*config)

type config struct {
	maxBodyBytes int64
	contentTypes []string
	autoDemask   bool
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// WithMaxBodyBytes limits the maximum number of bytes read from request body (default: 5 mb)
func WithMaxBodyBytes(limit int64) Option {
	return func(c *config) {
		if limit > 0 {
			c.maxBodyBytes = limit
		}
	}
}

// WithContentTypes restricts redaction only to requests matching specified Content-Types
func WithContentTypes(types ...string) Option {
	return func(c *config) {
		c.contentTypes = types
	}
}

// WithAutoDemask enables automatic replacement of tokens in the HTTP response body
func WithAutoDemask(enabled bool) Option {
	return func(c *config) {
		c.autoDemask = enabled
	}
}

func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(c *config) {
		c.errorHandler = fn
	}
}

func defaultConfig() *config {
	return &config{
		maxBodyBytes: 5 * 1024 * 1024,
		contentTypes: []string{"application/json", "text/plain", "application/x-www-form-urlencoded"},
		autoDemask:   false,
		errorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Failed to redact request payload", http.StatusInternalServerError)
		},
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
