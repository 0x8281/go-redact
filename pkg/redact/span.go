package redact

import "sort"

// MergeSpans sorts and merges overlapping or adjacent byte spans
func MergeSpans(spans []Span) []Span {
	if len(spans) <= 1 {
		return spans
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start == spans[j].Start {
			return spans[i].End > spans[j].End
		}
		return spans[i].Start < spans[j].Start
	})

	merged := make([]Span, 0, len(spans))
	merged = append(merged, spans[0])

	for i := 1; i < len(spans); i++ {
		curr := spans[i]
		last := &merged[len(merged)-1]

		if curr.Start >= last.Start && curr.End <= last.End {
			continue
		}

		if curr.Start < last.End {
			if curr.End > last.End {
				last.End = curr.End
			}
			continue
		}

		merged = append(merged, curr)
	}

	return merged
}
