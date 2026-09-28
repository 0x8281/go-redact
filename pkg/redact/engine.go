package redact

import (
	"context"
	"sort"
	"strings"
)

type Engine struct {
	detectors      []Detector
	strategy       Strategy
	compositeRules CompositeRule
}

type Option func(*Engine)

// WithStrategy sets the masking strategy (StrategyToken, StrategyAsterisks, StrategySynthetic)
func WithStrategy(s Strategy) Option {
	return func(e *Engine) {
		e.strategy = s
	}
}

// WithDetectors registers detection providers into the engine pipeline
func WithDetectors(detectors ...Detector) Option {
	return func(e *Engine) {
		e.detectors = append(e.detectors, detectors...)
	}
}

// WithCompositeRules enables contextual pruning of dependent spans lacking anchors
func WithCompositeRules(rules CompositeRule) Option {
	return func(e *Engine) {
		e.compositeRules = rules
	}
}

// New initializes a redaction engine with functional options
func New(opts ...Option) *Engine {
	e := &Engine{
		strategy: StrategyToken,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Mask runs detectors, applies composite filters, merges overlapping spans, and redacts text
func (e *Engine) Mask(ctx context.Context, text string) (Result, error) {
	if text == "" {
		return Result{Text: ""}, nil
	}

	var allSpans []Span
	for _, d := range e.detectors {
		spans, err := d.Detect(ctx, text)
		if err != nil {
			return Result{}, err
		}
		allSpans = append(allSpans, spans...)
	}

	if len(allSpans) == 0 {
		return Result{Text: text}, nil
	}

	if len(e.compositeRules) > 0 {
		allSpans = filterCompositeSpans(allSpans, e.compositeRules)
	}

	if len(allSpans) == 0 {
		return Result{Text: text}, nil
	}

	resolvedSpans := MergeSpans(allSpans)
	return e.applyStrategy(text, resolvedSpans), nil
}

// Demask restores original values in text using the provided mapping
func (e *Engine) Demask(text string, mapping map[string]string) string {
	return Demask(text, mapping)
}

// Demask replaces placeholders or synthetic values back with the original sensitive data.
func Demask(text string, mapping map[string]string) string {
	if len(mapping) == 0 || text == "" {
		return text
	}

	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	pairs := make([]string, 0, len(mapping)*2)
	for _, k := range keys {
		pairs = append(pairs, k, mapping[k])
	}

	return strings.NewReplacer(pairs...).Replace(text)
}
