package redact_test

import (
	"context"
	"testing"

	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func BenchmarkEngine_Mask(b *testing.B) {
	engine := redact.New(
		redact.WithStrategy(redact.StrategyToken),
		redact.WithDetectors(ru.DefaultDetectors()...),
		redact.WithCompositeRules(redact.DefaultCompositeRules),
	)

	text := `Уважаемый клиент Кузнецов Андрей Васильевич!
Напоминаем, что ваш паспорт серии 45 10 номер 123456 и СНИЛС 123-456-789 64
привязаны к договору. Перевод по карте 4276 3800 1234 5679 (CVV 777) поступит в 12:00.
Пишите на client-support@domain.ru.`

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := engine.Mask(ctx, text)
		if err != nil {
			b.Fatal(err)
		}
	}
}
