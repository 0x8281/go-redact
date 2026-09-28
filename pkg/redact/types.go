package redact

// Span describes the found sensitive entity in the text
// The Start and End coordinates are specified in byte offsets of the string slice
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// Strategy defines the behavior when sensitive data is replaced
type Strategy string

const (
	// StrategyToken replaces sensitive values with structured placeholder tokens (e.g., [FIO_1], [PHONE_1])
	StrategyToken Strategy = "token"

	// StrategyAsterisks partially masks values using asterisks, preserving partial context (e.g., J***n, ****-1234)
	StrategyAsterisks Strategy = "asterisks"

	// StrategySynthetic replaces sensitive values with realistic fake data matching the original format
	StrategySynthetic Strategy = "synthetic"
)

// Result contains the result of the masking pipeline
type Result struct {
	Text     string            `json:"text"`
	Spans    []Span            `json:"span"`
	Mapping  map[string]string `json:"mapping,omitempty"`
	Detected []string          `json:"detected"`
}
