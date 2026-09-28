package redact_test

import (
	"context"
	"testing"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func TestCompositeRules(t *testing.T) {
	engine := redact.New(
		redact.WithStrategy(redact.StrategyToken),
		redact.WithDetectors(ru.DefaultDetectors()...),
		redact.WithCompositeRules(redact.DefaultCompositeRules),
	)

	isolatedCVV := "Мой защитный код 890, никому не говори."
	res1, err := engine.Mask(context.Background(), isolatedCVV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsType(res1.Detected, "CVV") {
		t.Errorf("isolated CVV should not trigger without CARD anchor: %s", res1.Text)
	}

	cardWithCVV := "Карта 4276 3800 1234 5679, код 890."
	res2, err := engine.Mask(context.Background(), cardWithCVV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsType(res2.Detected, "CARD") || !containsType(res2.Detected, "CVV") {
		t.Errorf("expected both CARD and CVV to be detected, got: %v", res2.Detected)
	}
}
