package redact_test

import (
	"context"
	"strings"
	"testing"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func TestSyntheticSafety(t *testing.T) {
	engine := redact.New(
		redact.WithStrategy(redact.StrategySynthetic),
		redact.WithDetectors(ru.DefaultDetectors()...),
	)

	input := "Заказ оформил Соколов."
	res, err := engine.Mask(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	llmResponse := res.Text + " В зоопарке кормят соколов."
	restored := redact.Demask(llmResponse, res.Mapping)

	if !strings.Contains(restored, "кормят соколов") {
		t.Fatalf("Common word was corrupted during demasking: %s", restored)
	}

	if !strings.HasPrefix(restored, "Заказ оформил Соколов.") {
		t.Fatalf("Original PII was not restored properly: %s", restored)
	}
}
