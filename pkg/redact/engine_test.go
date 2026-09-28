package redact_test

import (
	"context"
	"slices"
	"testing"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func TestEngine_MaskAndDemask(t *testing.T) {
	engine := redact.New(
		redact.WithStrategy(redact.StrategyToken),
		redact.WithDetectors(ru.DefaultDetectors()...),
	)

	input := "Клиент Иванов Алексей Сергеевич, телефон +7 999 111-22-33, снилс 123-456-789 64."

	res, err := engine.Mask(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("Masked: %s", res.Text)

	if !containsType(res.Detected, "FIO") {
		t.Errorf("expected FIO to be detected, got %v", res.Detected)
	}
	if !containsType(res.Detected, "PHONE") {
		t.Errorf("expected PHONE to be detected, got %v", res.Detected)
	}

	restored := redact.Demask(res.Text, res.Mapping)
	if restored != input {
		t.Errorf("Demask failed.\nExpected: %s\nGot:      %s", input, restored)
	}
}

func containsType(arr []string, target string) bool {
	return slices.Contains(arr, target)
}
