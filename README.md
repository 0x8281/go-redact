# go-redact

`go-redact` is a fast, zero-dependency Personally Identifiable Information (PII) redaction and reversible anonymization library for Go.

Designed specifically as a privacy gateway for LLM pipelines and log sanitization, with first-class support for Russian regulatory compliance (152-ФЗ), document checksum algorithms, and Slavic name morphology.

---

## Architecture Flow

```text
 Client Input                                                 LLM Response
 ("Send 5k to card                                            ("Sent confirmation
  4276... and email user@mail.ru")                             to [EMAIL_1] for [CARD_1]")
         │                                                              │
         ▼                                                              │
┌──────────────────┐                                                    │
│  redact.Mask()   │                                                    │
└────────┬─────────┘                                                    │
         │                                                              ▼
         ├─────────────────► Masked Mapping ───────────────────►┌──────────────────┐
         │                   {[CARD_1]: 4276...,                │ redact.Demask()  │
         │                    [EMAIL_1]: user@mail.ru}          └────────┬─────────┘
         ▼                                                              │
   Anonymized Text                                                      ▼
 ("Send 5k to card [CARD_1]                                    Restored Output
  and email [EMAIL_1]")                                       ("Sent confirmation
         │                                                     to user@mail.ru for 4276...")
         ▼
┌──────────────────┐
│   LLM Service    │
│ (OpenAI, Claude) │
└──────────────────┘

```

---

## Features

* **Zero External Dependencies**: Implemented strictly using the Go standard library (`regexp`, `unicode/utf8`, `strings`).
* **Mathematical Checksums**: Rigorous validation algorithms to prevent false positives:
* **Payment Cards**: ISO/IEC 7812-1 Luhn algorithm.
* **SNILS (СНИЛС)**: Official Russian pension fund weighted checksum (modulo 101).
* **INN (ИНН)**: 10-digit (corporate) and 12-digit (individual) tax ID checksum verification.


* **Russian Morphological FIO Engine**: Accurately recognizes Russian full names across noun cases, inflections, patronymic suffixes (`-ович`, `-евна`), initials (`И.И. Иванов`), and filters common nouns / famous personalities.
* **Contextual Composite Rules**: Dependent credentials (such as CVV, PIN, or Card Expiry) are only redacted if their primary anchor (a valid `CARD` number) is present in the text.
* **Reversible Masking Strategies**:
* `StrategyToken`: Deterministic placeholders (`[FIO_1]`, `[CARD_1]`).
* `StrategyAsterisks`: Traditional redaction (`И***в`, `****-****-****-5679`).
* `StrategySynthetic`: Context-aware realistic fake entities wrapped with invisible zero-width boundaries (`\u200B`) to eliminate token collision during demasking.

## Roadmap

We are actively developing `go-redact`. Planned features and ongoing tasks include:

### 1. Framework Integrations & Transport
- [x] **HTTP Middlewares**: Ready-to-use middleware packages for `net/http`, [Gin](https://github.com/gin-gonic/gin), and [Fiber](https://github.com/gofiber/fiber) to sanitize request bodies before business handlers execute.
- [ ] **Drop-in LLM Reverse Proxy (`cmd/proxy`)**: A standalone transparent proxy server compatible with OpenAI, Anthropic, and Ollama APIs that automatically masks incoming prompts and demasks outgoing SSE streams.
- [ ] **gRPC Interceptor**: Client and server interceptors for automated field scrubbing in protobuf payloads.

### 2. Streaming & LLM Pipeline
- [ ] **Chunked SSE Stream Demasking**: Buffer and reconstruct token streams (Server-Sent Events) in real-time, handling tokens split across multiple chunks without breaking placeholders or synthetic values.
- [ ] **Structured JSON Redaction**: Smart traversal for JSON payloads to redact sensitive values while preserving keys, arrays, and syntax trees.

### 3. Multi-Locale Support
- [ ] **US Detector Pack (`detector/us`)**:
  - Social Security Numbers (SSN) with area/group validations.
  - Employer Identification Numbers (EIN).
  - US phone numbers, addresses, and state driver's licenses.
- [ ] **EU / Global Detector Pack (`detector/eu`)**:
  - International Bank Account Numbers (IBAN) with MOD 97-10 verification.
  - Value Added Tax (VAT) identification numbers across EU member states.
  - National IDs (e.g., UK National Insurance Number, Italian Codice Fiscale).

### 4. Engine & Performance Optimizations
- [ ] **Fast-Path Prefilters**: Byte-level fast scanning (`strings.IndexByte`, digit checks) to bypass regex engines entirely on non-matching payloads.
- [ ] **Aho-Corasick String Search**: Replace sequential dictionary checks for names, stop words, and roles with an Aho-Corasick automaton for $O(N)$ multi-pattern lookup.
- [ ] **Buffer Pooling**: Adopt `sync.Pool` across builders and tokenizers to reduce heap allocations down to near-zero.

---

## Installation

```bash
go get github.com/0x8281/go-redact

```

---

## Quickstart

```go
package main

import (
	"context"
	"fmt"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func main() {
	// 1. Initialize engine with default detectors and contextual composite rules
	engine := redact.New(
		redact.WithStrategy(redact.StrategyToken),
		redact.WithDetectors(ru.DefaultDetectors()...),
		redact.WithCompositeRules(redact.DefaultCompositeRules),
	)

	prompt := "Клиент Кузнецов Андрей Васильевич перевел деньги на карту 4276 3800 1234 5679 (CVV 890). Почта: user@domain.ru"

	// 2. Anonymize user input before forwarding to third-party LLM
	result, err := engine.Mask(context.Background(), prompt)
	if err != nil {
		panic(err)
	}

	fmt.Println("Masked:", result.Text)
	// Output:
	// Masked: Клиент [FIO_1] перевел деньги на карту [CARD_1] (CVV [CVV_1]). Почта: [EMAIL_1]

	// 3. Simulate an LLM output referencing placeholders
	llmOutput := "Операция подтверждена для [FIO_1]. Чек отправлен на [EMAIL_1]."

	// 4. Restore original sensitive data in the final client-facing output
	restored := redact.Demask(llmOutput, result.Mapping)
	fmt.Println("Restored:", restored)
	// Output:
	// Restored: Операция подтверждена для Кузнецов Андрей Васильевич. Чек отправлен на user@domain.ru.
}

```

---

## Supported Detectors

| Type | Target Entity | Detection Method / Verification |
| --- | --- | --- |
| `FIO` | Russian Full Names & Initials | Morphological suffix analysis, noun cases, stop-word pruning |
| `CARD` | Debit & Credit Card Numbers | Length heuristics + Luhn check digit validation |
| `CVV` | Card Security Codes (CVV/CVC) | Contextual keyword / position anchor + `CARD` dependency |
| `CARD_EXP` | Card Expiration Dates | Slash/prefix regex + date sanity (current/future verification) |
| `PIN` | ATM PIN Codes | Keyword matching + `CARD` composite anchor |
| `SNILS` | Pension Insurance Number (СНИЛС) | Regex matching + weighted modulo 101 checksum calculation |
| `INN` | Taxpayer ID (ИНН) | 10 and 12-digit weighted coefficient checksum validation |
| `PASSPORT` | Russian Internal Passport | Series (4 digits) + Number (6 digits) pattern |
| `PASSPORT_INTL` | International Russian Passport | Series (2 digits) + Number (7 digits) |
| `PASS_CODE` | Division / Authority Code | 6-digit subdivision code (`XXX-XXX`) |
| `PASS_AUTHORITY` | Issuing Authority Name | Department prefix matching (`ОВД`, `ГУ МВД`, `ТП`) |
| `DRIVER_LICENSE` | Driver's License | Standard Russian format matching |
| `EMAIL` | Email Addresses | RFC-compliant standard email pattern |
| `PHONE` | Russian Phone Numbers | E.164, national prefixes (`+7`, `8`), brackets, dashes |
| `DATE` | Calendar Dates | Numeric (`DD.MM.YYYY`, `YYYY-MM-DD`) and textual dates |

---

## Masking Strategies

### 1. `StrategyToken` (Default)

Replaces entities with unambiguous placeholders indexed by position. Recommended for standard LLM prompt sanitization.

```text
Original: "Позвоните Иванову на +7 999 111-22-33"
Masked:   "Позвоните [FIO_1] на [PHONE_1]"

```

### 2. `StrategyAsterisks`

Masks internal runes with `*` while retaining structural delimiters and outer characters for readability. Suitable for audit logs.

```text
Original: "Карта 4276 3800 1234 5679"
Masked:   "Карта 4*** **** **** 5679"

```

### 3. `StrategySynthetic`

Replaces PII with realistic Russian names, addresses, and documents. Uses invisible zero-width boundary runes (`\u200B`) to guarantee that regular vocabulary matching generated fake tokens is not accidentally rewritten during `Demask`.

```text
Original: "Клиент Петров живет в г. Самара"
Masked:   "Клиент ​​Смирнов​​ живет в г. ​​Москва​​"

```

---

## Custom Detectors

Any struct implementing the `redact.Detector` interface can be plugged into the engine:

```go
type Detector interface {
    Type() string
    Detect(ctx context.Context, text string) ([]redact.Span, error)
}

```

Example creating a regex detector for custom corporate contract IDs:

```go
contractDetector := detector.NewRule(
    "CONTRACT_ID", 
    regexp.MustCompile(`\bCTR-\d{6}\b`),
)

engine := redact.New(
    redact.WithDetectors(contractDetector),
)

```

---

## Benchmarks

Measured on an Apple M2 (8-core, 16 GB unified memory) with 14 active detectors, Luhn check, SNILS/INN checksum verification, composite filtering, and token extraction:

```bash
go test -bench=. -benchmem ./pkg/redact/...

```

```text
goos: darwin
goarch: arm64
pkg: github.com/0x8281/go-redact/pkg/redact
BenchmarkEngine_Mask-8    3722    317459 ns/op    7369 B/op    55 allocs/op

```

* **Latency**: ~0.31 ms per operation (under 0.01% overhead for typical LLM API roundtrips).
* **Allocations**: 55 allocations / 7.3 KB per payload.

---

## License

This project is licensed under the MIT License — see the [LICENSE](https://www.google.com/search?q=LICENSE&utm_source=gemini) file for details.
