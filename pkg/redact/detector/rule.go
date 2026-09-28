package detector

import (
	"context"
	"regexp"

	"github.com/0x8281/go-redact/pkg/redact"
)

// ValidatorFunc verifies if the matched text is valid (e.g. checksum check)
type ValidatorFunc func(match string) bool

// RuleDetector matches text using regex and optional validator functions
type RuleDetector struct {
	dataType  string
	pattern   *regexp.Regexp
	subgroups []int
	validate  ValidatorFunc
}

// RuleOption configures a RuleDetector
type RuleOption func(*RuleDetector)

// WithSubgroups specifies regex capturing group indexes to extract
func WithSubgroups(groups ...int) RuleOption {
	return func(r *RuleDetector) {
		r.subgroups = groups
	}
}

// WithValidator attaches a checksum or semantic validator
func WithValidator(v ValidatorFunc) RuleOption {
	return func(r *RuleDetector) {
		r.validate = v
	}
}

// NewRule creates a new regex-based Detector.
func NewRule(dataType string, pattern *regexp.Regexp, opts ...RuleOption) *RuleDetector {
	rd := &RuleDetector{
		dataType: dataType,
		pattern:  pattern,
	}
	for _, opt := range opts {
		opt(rd)
	}
	return rd
}

// Type returns the entity type name
func (r *RuleDetector) Type() string {
	return r.dataType
}

// Detect scans input text and extracts matching spans
func (r *RuleDetector) Detect(ctx context.Context, text string) ([]redact.Span, error) {
	if text == "" {
		return nil, nil
	}

	matches := r.pattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var spans []redact.Span

	for _, m := range matches {
		if len(r.subgroups) == 0 {
			start, end := m[0], m[1]
			val := text[start:end]
			if r.validate == nil || r.validate(val) {
				spans = append(spans, redact.Span{
					Start: start,
					End:   end,
					Type:  r.dataType,
					Value: val,
				})
			}
			continue
		}

		for _, groupIdx := range r.subgroups {
			sIdx := groupIdx * 2
			eIdx := sIdx + 1
			if len(m) > eIdx && m[sIdx] >= 0 {
				start, end := m[sIdx], m[eIdx]
				val := text[start:end]
				if r.validate == nil || r.validate(val) {
					spans = append(spans, redact.Span{
						Start: start,
						End:   end,
						Type:  r.dataType,
						Value: val,
					})
				}
			}
		}
	}

	return spans, nil
}
