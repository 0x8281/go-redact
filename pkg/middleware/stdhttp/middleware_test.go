package stdhttp_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x8281/go-redact/pkg/middleware/stdhttp"
	"github.com/0x8281/go-redact/pkg/redact"
	"github.com/0x8281/go-redact/pkg/redact/detector/ru"
)

func TestMiddleware_MaskAndAutoDemask(t *testing.T) {
	engine := redact.New(
		redact.WithStrategy(redact.StrategyToken),
		redact.WithDetectors(ru.DefaultDetectors()...),
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body in handler: %v", err)
		}

		res, ok := stdhttp.FromContext(r.Context())
		if !ok {
			t.Fatal("expected Result in context, found none")
		}

		if len(res.Detected) == 0 {
			t.Fatal("expected detected PII entities in Result")
		}

		expectedMasked := `{"prompt":"Свяжись со мной по почте [EMAIL_1]"}`
		if string(body) != expectedMasked {
			t.Fatalf("unexpected handler body:\nExpected: %s\nGot:      %s", expectedMasked, string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"Ответ отправлен на адрес [EMAIL_1]"}`))
	})

	mw := stdhttp.Middleware(
		engine,
		stdhttp.WithAutoDemask(true),
	)

	server := httptest.NewServer(mw(handler))
	defer server.Close()

	payload := []byte(`{"prompt":"Свяжись со мной по почте test@domain.ru"}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	expectedResponse := `{"reply":"Ответ отправлен на адрес test@domain.ru"}`

	if string(respBody) != expectedResponse {
		t.Fatalf("Demask failed on response:\nExpected: %s\nGot:      %s", expectedResponse, string(respBody))
	}

	err = resp.Body.Close()
	if err != nil {
		t.Fatalf("close body %v", err)
	}
}
