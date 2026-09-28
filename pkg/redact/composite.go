package redact

// CompositeRule maps a dependent entity type to required anchor types
// A dependent span is retained only if at least one anchor type was also detected
type CompositeRule map[string][]string

// DefaultCompositeRules defines common cryptographic and financial dependency constraints
var DefaultCompositeRules = CompositeRule{
	"PIN":      {"CARD"},
	"CVV":      {"CARD"},
	"CARD_EXP": {"CARD"},
}

// filterCompositeSpans filters out dependent spans that lack any of their required anchors in detected spans
func filterCompositeSpans(spans []Span, rules CompositeRule) []Span {
	if len(rules) == 0 || len(spans) == 0 {
		return spans
	}

	presentTypes := make(map[string]bool, len(spans))
	for _, sp := range spans {
		presentTypes[sp.Type] = true
	}

	filtered := spans[:0]
	for _, sp := range spans {
		anchors, exists := rules[sp.Type]
		if !exists {
			filtered = append(filtered, sp)
			continue
		}

		hasAnchor := false
		for _, anchor := range anchors {
			if presentTypes[anchor] {
				hasAnchor = true
				break
			}
		}

		if hasAnchor {
			filtered = append(filtered, sp)
		}
	}

	return filtered
}
