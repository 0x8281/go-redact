package stdhttp

import (
	"context"

	"github.com/0x8281/go-redact/pkg/redact"
)

type contextKey struct{}

var resultKey = contextKey{}

// WithResult stores the redaction Result inside the request context
func WithResult(ctx context.Context, res redact.Result) context.Context {
	return context.WithValue(ctx, resultKey, res)
}

// FromContext extracts the redaction result from the request context
func FromContext(ctx context.Context) (redact.Result, bool) {
	val := ctx.Value(resultKey)
	if val == nil {
		return redact.Result{}, false
	}

	res, ok := val.(redact.Result)

	return res, ok
}
