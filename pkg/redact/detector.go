package redact

import "context"

// Detector defines detecotr interface
type Detector interface {
	Type() string
	Detect(ctx context.Context, text string) ([]Span, error)
}
