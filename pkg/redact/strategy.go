package redact

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	zeroWidthPrefix = "\u200B"
	zeroWidthSuffix = "\u200B"
)

func (e *Engine) applyStrategy(text string, spans []Span) Result {
	if len(spans) == 0 {
		return Result{Text: text}
	}

	detectedSet := make(map[string]struct{}, len(spans))
	for _, sp := range spans {
		detectedSet[sp.Type] = struct{}{}
	}
	detected := make([]string, 0, len(detectedSet))
	for typ := range detectedSet {
		detected = append(detected, typ)
	}
	sort.Strings(detected)

	switch e.strategy {
	case StrategyAsterisks:
		masked := applyAsterisks(text, spans)
		return Result{
			Text:     masked,
			Spans:    spans,
			Detected: detected,
		}

	case StrategySynthetic:
		masked, mapping := applySynthetic(text, spans)
		return Result{
			Text:     masked,
			Spans:    spans,
			Mapping:  mapping,
			Detected: detected,
		}

	default:
		masked, mapping := applyTokens(text, spans)
		return Result{
			Text:     masked,
			Spans:    spans,
			Mapping:  mapping,
			Detected: detected,
		}
	}
}

func applyTokens(text string, spans []Span) (string, map[string]string) {
	var sb strings.Builder
	sb.Grow(len(text))

	mapping := make(map[string]string, len(spans))
	counters := make(map[string]int)
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(text[lastIdx:span.Start])

		counters[span.Type]++
		placeholder := fmt.Sprintf("[%s_%d]", span.Type, counters[span.Type])
		mapping[placeholder] = text[span.Start:span.End]

		sb.WriteString(placeholder)
		lastIdx = span.End
	}
	sb.WriteString(text[lastIdx:])

	return sb.String(), mapping
}

func applyAsterisks(text string, spans []Span) string {
	var sb strings.Builder
	sb.Grow(len(text))
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(text[lastIdx:span.Start])

		rawSpan := text[span.Start:span.End]
		runes := []rune(rawSpan)
		rLen := len(runes)

		for i, r := range runes {
			if unicode.IsSpace(r) || r == '-' || r == '.' || r == '@' || r == '+' {
				sb.WriteRune(r)
			} else if rLen > 4 && (i == 0 || i == rLen-1) {
				sb.WriteRune(r)
			} else {
				sb.WriteRune('*')
			}
		}
		lastIdx = span.End
	}
	sb.WriteString(text[lastIdx:])

	return sb.String()
}

func applySynthetic(text string, spans []Span) (string, map[string]string) {
	var sb strings.Builder
	sb.Grow(len(text))

	mapping := make(map[string]string, len(spans))
	counters := make(map[string]int)
	used := make(map[string]bool)
	lastIdx := 0

	for _, span := range spans {
		if span.Start < lastIdx {
			continue
		}
		sb.WriteString(text[lastIdx:span.Start])

		original := text[span.Start:span.End]
		counters[span.Type]++
		bareFake := generateSyntheticValue(span.Type, original, counters[span.Type], used)
		used[bareFake] = true

		wrappedFake := zeroWidthPrefix + bareFake + zeroWidthSuffix
		mapping[wrappedFake] = original

		sb.WriteString(wrappedFake)
		lastIdx = span.End
	}
	sb.WriteString(text[lastIdx:])

	return sb.String(), mapping
}

var (
	synthLastNames  = []string{"Смирнов", "Кузнецов", "Попов", "Соколов", "Лебедев", "Козлов", "Новиков", "Морозов", "Волков", "Зайцев"}
	synthFirstNames = []string{"Петр", "Иван", "Сергей", "Алексей", "Дмитрий", "Николай", "Андрей", "Михаил", "Егор", "Роман"}
	synthPatronyms  = []string{"Петрович", "Иванович", "Сергеевич", "Алексеевич", "Дмитриевич", "Николаевич"}
	synthCities     = []string{"Москва", "Санкт-Петербург", "Казань", "Нижний Новгород", "Самара", "Екатеринбург"}
)

func generateSyntheticValue(typ, original string, counter int, used map[string]bool) string {
	for attempt := 0; ; attempt++ {
		n := counter + attempt
		var val string

		switch typ {
		case "FIO":
			words := len(strings.Fields(original))
			last := synthLastNames[n%len(synthLastNames)]
			first := synthFirstNames[(n/len(synthLastNames))%len(synthFirstNames)]
			switch {
			case words <= 1:
				val = last
			case words == 2:
				val = last + " " + first
			default:
				val = last + " " + first + " " + synthPatronyms[n%len(synthPatronyms)]
			}
		case "PHONE":
			val = fmt.Sprintf("+7 9%02d %03d-%02d-%02d", n%100, (n*7)%1000, n%100, (n*3)%100)
		case "EMAIL":
			val = fmt.Sprintf("user%d@example.com", n)
		case "CARD":
			val = synthLuhnCard(n)
		case "PASSPORT":
			val = fmt.Sprintf("%02d %02d %06d", 40+n%50, 10+n%89, (n*137)%1000000)
		case "SNILS":
			val = fmt.Sprintf("%03d-%03d-%03d %02d", n%1000, (n*3)%1000, (n*7)%1000, n%100)
		case "INN":
			val = fmt.Sprintf("%012d", int64(n)*104729%1000000000000)
		case "CITY", "ADDRESS":
			val = synthCities[n%len(synthCities)]
		default:
			val = fmt.Sprintf("[%s_%d]", typ, counter)
		}

		if !used[val] {
			return val
		}
	}
}

func synthLuhnCard(n int) string {
	base := fmt.Sprintf("4%014d", n%100000000000000)
	sum, alt := 0, true
	for i := len(base) - 1; i >= 0; i-- {
		d := int(base[i] - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	check := (10 - sum%10) % 10
	full := base + strconv.Itoa(check)
	return full[0:4] + " " + full[4:8] + " " + full[8:12] + " " + full[12:16]
}
