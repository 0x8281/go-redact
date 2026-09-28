package ru

import (
	"regexp"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector"
)

var (
	reDriverLicense = regexp.MustCompile(`(?i)(?:водительск[а-яё]*|в/у|удостоверени[а-яё]*)[^\d]*?(\b\d{2}\s*(?:\d{2}|[А-ЯA-Z]{2})\s*\d{6}\b)`)

	rePassportIntl = regexp.MustCompile(`(?i)загран\p{L}*\D{0,20}?(\d{2})\s*(?:№|номер)?\s*(\d{7})\b`)

	rePassCode = regexp.MustCompile(`\b\d{3}-\d{3}\b`)

	rePassAuthority = regexp.MustCompile(`(?i)(?:выдан[оаы]?\s+)?((?:ГУ\s?МВД|У?МВД|Р[ОУ]ВД|ОВД|ОВМ|ГУВД|О?УФМС|ТП)(?:\s+(?:росси[ий]|рф|[а-яё]+)){0,3})`)

	reDateNumeric = regexp.MustCompile(`\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b`)
	reDateTextual = regexp.MustCompile(`(?i)\b\d{1,2}\s+(?:янв|фев|мар|апр|ма[йя]|июн|июл|авг|сен|окт|ноя|дек)[а-яё]*\.?\s+\d{2,4}(?:\s*г(?:ода|\.)?)?`)
)

// DocumentDetectors returns detectors for additional Russian identity documents and timestamps
func DocumentDetectors() []redact.Detector {
	return []redact.Detector{
		detector.NewRule("DRIVER_LICENSE", reDriverLicense, detector.WithSubgroups(1)),
		detector.NewRule("PASSPORT_INTL", rePassportIntl, detector.WithSubgroups(1, 2)),
		detector.NewRule("PASS_CODE", rePassCode),
		detector.NewRule("PASS_AUTHORITY", rePassAuthority, detector.WithSubgroups(1)),
		detector.NewRule("DATE", reDateNumeric),
		detector.NewRule("DATE", reDateTextual),
	}
}
