package ru

import (
	"context"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0x8281/go-redact/pkg/redact"
)

var (
	reFIOInitialsL = regexp.MustCompile(`[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.`)
	reFIOInitialsR = regexp.MustCompile(`[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+`)
	reFIOMarkers   = regexp.MustCompile(`(?i)(?:на\s+имя|ф\.?\s?и\.?\s?о\.?)\s*[:\-]?\s+([а-яёa-z]+(?:\s+[а-яёa-z]+){1,2})`)

	surnameSuffixes = []string{
		"ова", "ева", "ёва", "ина", "ына", "ская", "цкая",
		"ский", "цкий", "янц", "идзе", "адзе", "швили", "енко",
		"ов", "ев", "ёв", "ин", "ын", "ян", "ко", "ук", "юк", "их", "ых",
	}

	patronymicSuffixes = []string{"ович", "евич", "овна", "евна", "инична", "ична"}
)

// FIODetector recognizes Russian full names (Surname, First Name, Patronymic)
// using morphological heuristics, common affixes, and dictionary lookups
type FIODetector struct {
	stopTokens  map[string]struct{}
	roleWords   map[string]struct{}
	famousNames map[string]struct{}
	givenNames  map[string]struct{}
	commonNouns map[string]struct{}
	weakStop    map[string]struct{}
}

// NewFIODetector initializes a detector configured with default Russian naming dictionaries
func NewFIODetector() *FIODetector {
	d := &FIODetector{
		stopTokens: toSet([]string{
			"москва", "россия", "россии", "российская", "российской", "федерация",
			"федерации", "санкт", "петербург", "сити", "банк", "банка", "банке",
			"ао", "оао", "пао", "ооо", "зао", "офис", "отделение", "проспект",
		}),
		roleWords: toSet([]string{
			"клиент", "клиента", "клиенту", "гражданин", "гражданина", "гражданка",
			"заявитель", "заявителя", "плательщик", "получатель", "держатель",
			"поэт", "писатель", "автор", "господин", "госпожа", "товарищ", "пациент",
			"абонент", "сотрудник", "директор", "менеджер", "президент", "министр",
			"депутат", "уважаемый", "уважаемая", "дорогой", "дорогая",
		}),
		famousNames: toSet([]string{
			"александр пушкин", "лев толстой", "федор достоевский", "фёдор достоевский",
			"антон чехов", "иван тургенев", "николай гоголь", "михаил лермонтов",
			"сергей есенин", "владимир маяковский", "александр сергеевич пушкин",
		}),
		givenNames: toSet(expandInflections([]string{
			"александр", "алексей", "анатолий", "андрей", "антон", "аркадий", "артём", "артем",
			"борис", "вадим", "валентин", "валерий", "василий", "виктор", "виталий", "владимир",
			"владислав", "вячеслав", "геннадий", "георгий", "григорий", "даниил", "денис", "дмитрий",
			"евгений", "егор", "иван", "игорь", "илья", "кирилл", "константин", "леонид", "максим",
			"михаил", "никита", "николай", "олег", "павел", "пётр", "петр", "роман", "руслан",
			"сергей", "станислав", "степан", "тимофей", "фёдор", "федор", "эдуард", "юрий", "ярослав",
			"алла", "анастасия", "анна", "валентина", "вера", "виктория", "галина", "дарья", "дина",
			"екатерина", "елена", "ирина", "кристина", "лариса", "любовь", "людмила", "маргарита",
			"марина", "мария", "надежда", "наталья", "наталия", "нина", "оксана", "ольга", "полина",
			"светлана", "софия", "софья", "тамара", "татьяна", "юлия",
		})),
		weakStop: toSet([]string{
			"и", "в", "во", "на", "с", "со", "по", "для", "от", "до", "за", "о", "об",
			"у", "к", "из", "а", "но", "же", "ли", "бы", "не", "что", "как", "это",
			"его", "её", "ее", "им", "их", "ему", "ей", "мне", "нам", "вам", "тебе",
			"был", "была", "были", "есть", "сказал", "сказала", "пришёл", "пришла",
		}),
		commonNouns: toSet([]string{
			"бензин", "магазин", "машина", "картина", "корзина", "причина", "витрина",
			"долина", "вершина", "малина", "рябина", "паутина", "пружина", "калина",
			"година", "равнина", "морщина", "величина", "мужчина", "женщина", "община",
			"молоко", "окно", "далеко", "давно", "число", "слово", "право", "утро",
			"здоров", "готов", "остров", "покров", "улов", "засов", "обзор",
		}),
	}
	return d
}

// Type returns "FIO"
func (d *FIODetector) Type() string {
	return "FIO"
}

// Detect identifies Russian names and initials within input text
func (d *FIODetector) Detect(ctx context.Context, text string) ([]redact.Span, error) {
	if text == "" {
		return nil, nil
	}

	var spans []redact.Span

	for _, re := range []*regexp.Regexp{reFIOInitialsL, reFIOInitialsR} {
		for _, m := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, redact.Span{
				Start: m[0],
				End:   m[1],
				Type:  "FIO",
				Value: text[m[0]:m[1]],
			})
		}
	}

	for _, m := range reFIOMarkers.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			spans = append(spans, redact.Span{
				Start: m[2],
				End:   m[3],
				Type:  "FIO",
				Value: text[m[2]:m[3]],
			})
		}
	}

	morphSpans := d.findMorphologicalSpans(text)
	spans = append(spans, morphSpans...)

	return spans, nil
}

type textToken struct {
	start int
	end   int
	raw   string
	low   string
}

func (d *FIODetector) findMorphologicalSpans(text string) []redact.Span {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return nil
	}

	var spans []redact.Span
	i := 0

	for i < len(tokens) {
		matched := false
		for w := 3; w >= 1; w-- {
			if i+w > len(tokens) {
				continue
			}
			if !areAdjacent(text, tokens, i, i+w-1) {
				continue
			}

			nameLike, strong := 0, 0
			for k := 0; k < w; k++ {
				nl, st := d.classify(tokens[i+k].low)
				if nl {
					nameLike++
				}
				if st {
					strong++
				}
			}

			ok := false
			if w >= 2 {
				ok = (nameLike == w && strong >= 1)
				if !ok && w == 3 && strong >= 1 {
					nl0, _ := d.classify(tokens[i].low)
					nl2, _ := d.classify(tokens[i+2].low)
					if nl0 && nl2 && !d.isDisqualified(tokens[i+1].low) {
						ok = true
					}
				}
			} else {
				ok = isPatronymic(tokens[i].low)
			}

			if ok && !d.isFalsePositive(tokens[i:i+w]) {
				start := tokens[i].start
				end := tokens[i+w-1].end
				spans = append(spans, redact.Span{
					Start: start,
					End:   end,
					Type:  "FIO",
					Value: text[start:end],
				})
				i += w
				matched = true
				break
			}
		}

		if !matched {
			i++
		}
	}

	return spans
}

func tokenize(s string) []textToken {
	var tokens []textToken
	inWord := false
	start := 0

	for i, r := range s {
		if unicode.IsLetter(r) {
			if !inWord {
				inWord = true
				start = i
			}
		} else {
			if inWord {
				tokens = append(tokens, textToken{
					start: start,
					end:   i,
					raw:   s[start:i],
					low:   strings.ToLower(s[start:i]),
				})
				inWord = false
			}
		}
	}
	if inWord {
		tokens = append(tokens, textToken{
			start: start,
			end:   len(s),
			raw:   s[start:],
			low:   strings.ToLower(s[start:]),
		})
	}
	return tokens
}

func areAdjacent(text string, tokens []textToken, from, to int) bool {
	for k := from; k < to; k++ {
		gap := text[tokens[k].end:tokens[k+1].start]
		if len(gap) == 0 || len(gap) > 3 {
			return false
		}
		for i := 0; i < len(gap); i++ {
			b := gap[i]
			if b != ' ' && b != '\t' && b != '-' {
				return false
			}
		}
	}
	return true
}

func (d *FIODetector) classify(low string) (nameLike, strong bool) {
	if _, ok := d.commonNouns[low]; ok {
		return false, false
	}
	if _, ok := d.givenNames[low]; ok {
		return true, true
	}
	if isPatronymic(low) {
		return true, true
	}
	if utf8.RuneCountInString(low) >= 5 && hasAnySuffix(low, surnameSuffixes) {
		return true, false
	}
	return false, false
}

func (d *FIODetector) isDisqualified(low string) bool {
	if _, ok := d.commonNouns[low]; ok {
		return true
	}
	if _, ok := d.weakStop[low]; ok {
		return true
	}
	if _, ok := d.roleWords[low]; ok {
		return true
	}
	if _, ok := d.stopTokens[low]; ok {
		return true
	}
	return false
}

func (d *FIODetector) isFalsePositive(tokens []textToken) bool {
	for _, t := range tokens {
		if _, ok := d.stopTokens[t.low]; ok {
			return true
		}
	}
	if len(tokens) >= 2 {
		k1 := tokens[0].low + " " + tokens[1].low
		k2 := tokens[1].low + " " + tokens[0].low
		if _, ok := d.famousNames[k1]; ok {
			return true
		}
		if _, ok := d.famousNames[k2]; ok {
			return true
		}
		if len(tokens) == 3 {
			k3 := tokens[0].low + " " + tokens[1].low + " " + tokens[2].low
			if _, ok := d.famousNames[k3]; ok {
				return true
			}
		}
	}
	return false
}

func isPatronymic(low string) bool {
	return utf8.RuneCountInString(low) >= 5 && hasAnySuffix(low, patronymicSuffixes)
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func expandInflections(base []string) []string {
	out := make([]string, 0, len(base)*5)
	for _, n := range base {
		out = append(out, n)
		r := []rune(n)
		if len(r) < 3 {
			continue
		}
		stem := string(r[:len(r)-1])
		switch r[len(r)-1] {
		case 'й':
			out = append(out, stem+"я", stem+"ю", stem+"ем", stem+"е")
		case 'а':
			out = append(out, stem+"ы", stem+"е", stem+"у", stem+"ой")
		case 'я':
			out = append(out, stem+"и", stem+"е", stem+"ю", stem+"ей")
		default:
			out = append(out, n+"а", n+"у", n+"ом", n+"е", n+"ым")
		}
	}
	return out
}
