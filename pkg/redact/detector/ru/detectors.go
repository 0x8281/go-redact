package ru

import (
	"regexp"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector"
)

var (
	reEmail      = regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	rePhoneRU    = regexp.MustCompile(`(?:\+?[78])[\s\-.]*\(?\d{3}\)?[\s\-.]*\d{3}[\s\-.]*\d{2}[\s\-.]*\d{2}`)
	rePassportRU = regexp.MustCompile(`(?i)(?:паспорт\s*(?:рф)?[^\d]*?)?(\b\d{2}\s*\d{2}\s*\d{6}\b)`)
	reSNILS      = regexp.MustCompile(`\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}\b`)
	reINN        = regexp.MustCompile(`\b\d{10}\b|\b\d{12}\b`)
	reCardNumber = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
)

// DefaultDetectors returns production-ready detectors tailored for Russian locale
func DefaultDetectors() []redact.Detector {
	detectors := []redact.Detector{
		NewFIODetector(),
		NewCardMetaDetector(),
		detector.NewRule("EMAIL", reEmail),
		detector.NewRule("PHONE", rePhoneRU),
		detector.NewRule("PASSPORT", rePassportRU, detector.WithSubgroups(1)),
		detector.NewRule("SNILS", reSNILS, detector.WithValidator(ValidateSNILS)),
		detector.NewRule("INN", reINN, detector.WithValidator(ValidateINN)),
		detector.NewRule("CARD", reCardNumber, detector.WithValidator(ValidateLuhn)),
	}

	return append(detectors, DocumentDetectors()...)
}
