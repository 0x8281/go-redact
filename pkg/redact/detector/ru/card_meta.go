package ru

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/0x8281/go-redact/pkg/redact"
)

var (
	reCVVWithMarker = regexp.MustCompile(`(?i)(?:cvv|cvc|код)[^\d]{0,5}(\d{3}\b)`)
	rePINWithMarker = regexp.MustCompile(`(?i)(?:пин|pin)(?:[\s\-]?код)?[^\d]{0,12}(\d{4}\b)`)

	reExpSlash   = regexp.MustCompile(`\b(0[1-9]|1[0-2])/(\d{2}|\d{4})\b`)
	reExpContext = regexp.MustCompile(`(?i)(?:срок|действ|годн|карт[аеыой]|valid|expir|thru)\D{0,20}?(0[1-9]|1[0-2])[.\-/](\d{2}|\d{4})\b`)
)

// CardMetaDetector detects secondary payment card credentials (CVV, PIN, Expiry Date)
type CardMetaDetector struct {
	clock func() time.Time
}

// NewCardMetaDetector creates a detector for card auxiliary credentials
func NewCardMetaDetector() *CardMetaDetector {
	return &CardMetaDetector{
		clock: time.Now,
	}
}

// Type returns an identifier for the detector family
func (d *CardMetaDetector) Type() string {
	return "CARD_META"
}

// Detect scans input text for CVV, PIN, and expiration dates
func (d *CardMetaDetector) Detect(ctx context.Context, text string) ([]redact.Span, error) {
	if text == "" {
		return nil, nil
	}

	var spans []redact.Span

	for _, m := range reCVVWithMarker.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			spans = append(spans, redact.Span{
				Start: m[2],
				End:   m[3],
				Type:  "CVV",
				Value: text[m[2]:m[3]],
			})
		}
	}

	for _, m := range rePINWithMarker.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			spans = append(spans, redact.Span{
				Start: m[2],
				End:   m[3],
				Type:  "PIN",
				Value: text[m[2]:m[3]],
			})
		}
	}

	now := d.clock()
	for _, re := range []*regexp.Regexp{reExpSlash, reExpContext} {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if len(m) < 6 || m[2] < 0 || m[4] < 0 {
				continue
			}
			mm, _ := strconv.Atoi(text[m[2]:m[3]])
			yy, _ := strconv.Atoi(text[m[4]:m[5]])

			if isFutureExpiry(mm, yy, now) {
				spans = append(spans, redact.Span{
					Start: m[2],
					End:   m[5],
					Type:  "CARD_EXP",
					Value: text[m[2]:m[5]],
				})
			}
		}
	}

	return spans, nil
}

func isFutureExpiry(mm, yy int, now time.Time) bool {
	if mm < 1 || mm > 12 {
		return false
	}
	if yy < 100 {
		yy += 2000
	}
	currentYear := now.Year()
	if yy != currentYear {
		return yy > currentYear
	}
	return mm >= int(now.Month())
}
