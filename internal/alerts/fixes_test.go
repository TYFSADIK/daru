package alerts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCronDowSevenIsSunday(t *testing.T) {
	s, err := ParseCron("0 9 * * 7")
	if err != nil {
		t.Fatalf("ParseCron: %v", err)
	}
	// 2026-11-08 is a Sunday.
	if !s.Matches(at("2026-11-08 09:00")) {
		t.Error("dow 7 should match Sunday")
	}
	if s.Matches(at("2026-11-07 09:00")) {
		t.Error("dow 7 should not match Saturday")
	}
	s, err = ParseCron("0 9 * * 5-7")
	if err != nil {
		t.Fatalf("ParseCron: %v", err)
	}
	if !s.Matches(at("2026-11-08 09:00")) {
		t.Error("dow range 5-7 should include Sunday")
	}
}

func TestConditionStrict(t *testing.T) {
	for _, bad := range []string{"count > abc", "count > 10x", "count >", "count", "count >> 5"} {
		if _, err := conditionMetStrict(bad, 3); err == nil {
			t.Errorf("condition %q should fail", bad)
		}
	}
	if ok, err := conditionMetStrict("count > 5", 3); err != nil || ok {
		t.Errorf("count > 5 with 3 = %v %v, want false nil", ok, err)
	}
	if ok, err := conditionMetStrict("", 0); err != nil || ok {
		t.Errorf("empty condition with 0 = %v %v, want false nil", ok, err)
	}
	if err := ValidateCondition("count > abc"); err == nil {
		t.Error("ValidateCondition should reject count > abc")
	}
}

func TestParseActionsStrict(t *testing.T) {
	cfg, err := ParseActions(`{"severity":"high","actions":["notable","webhook"],"webhook_url":"https://example.com/hook","suppress_minutes":30,"mitre_tactic":"TA0001","mitre_technique":"T1078"}`)
	if err != nil {
		t.Fatalf("ParseActions: %v", err)
	}
	if cfg.Severity != "high" || !cfg.Actions["webhook"] || cfg.WebhookURL == "" || cfg.SuppressMin != 30 {
		t.Errorf("actions parsed wrong: %+v", cfg)
	}
	if cfg.MitreTactic != "TA0001" || cfg.MitreTechnique != "T1078" {
		t.Errorf("MITRE parsed wrong: %+v", cfg)
	}
	for _, bad := range []string{
		`{"severity":"nope"}`,
		`{"webhook_url":"ftp://example.com"}`,
		`{"suppress_minutes":-1}`,
		`{"mitre_tactic":"TA01"}`,
		`{"mitre_technique":"X1078"}`,
		`not json`,
	} {
		if _, err := ParseActions(bad); err == nil {
			t.Errorf("ParseActions(%q) should fail", bad)
		}
	}
}

func TestDefaultWindow(t *testing.T) {
	cases := map[string]string{
		"* * * * *": "-5m",
		"0 * * * *": "-1h",
		"0 0 * * *": "-24h",
		"0 0 * * 0": "-7d",
		"bad cron":  "-5m",
	}
	for cron, want := range cases {
		if got := DefaultWindow(cron); got != want {
			t.Errorf("DefaultWindow(%q) = %q, want %q", cron, got, want)
		}
	}
}

func TestWebhookNotifierRetriesOnce(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &webhookNotifier{url: srv.URL}
	if err := n.Notify(context.Background(), Fired{SearchName: "test", Severity: "high", ResultCount: 3}); err != nil {
		t.Fatalf("webhook should succeed on retry: %v", err)
	}
	if calls != 2 {
		t.Errorf("webhook calls = %d, want 2 (one retry)", calls)
	}
}

func TestWebhookNotifierRejectsClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	n := &webhookNotifier{url: srv.URL}
	if err := n.Notify(context.Background(), Fired{SearchName: "test"}); err == nil {
		t.Error("webhook 400 should fail without retry")
	}
}

func TestValidMitreID(t *testing.T) {
	if !ValidMitreID("TA0001", "TA") || !ValidMitreID("T1078", "T") || !ValidMitreID("T1078.001", "T") {
		t.Error("valid MITRE ids rejected")
	}
	if ValidMitreID("TA01", "TA") || ValidMitreID("T107", "T") || ValidMitreID("TA0001", "T") {
		t.Error("invalid MITRE ids accepted")
	}
}

var _ = fmt.Sprint
var _ = time.Now

func TestWebhookHMACSigning(t *testing.T) {
	secret := []byte("s3cret-for-test")
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(WebhookSignatureHeader)
		gotTS = r.Header.Get(WebhookTimestampHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	fixed := time.Unix(1_800_000_000, 0)
	n := &webhookNotifier{url: srv.URL, secret: secret, now: func() time.Time { return fixed }}
	if err := n.Notify(context.Background(), Fired{SearchName: "brute force", Severity: "high", ResultCount: 12}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotTS != "1800000000" || !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("missing signature headers: ts=%q sig=%q", gotTS, gotSig)
	}
	if !VerifyWebhook(secret, gotTS, gotSig, gotBody, fixed, 5*time.Minute) {
		t.Error("signature did not verify")
	}
	if VerifyWebhook([]byte("wrong"), gotTS, gotSig, gotBody, fixed, 5*time.Minute) {
		t.Error("signature verified with the wrong secret")
	}
	tampered := append([]byte{}, gotBody...)
	tampered[len(tampered)-2] ^= 1
	if VerifyWebhook(secret, gotTS, gotSig, tampered, fixed, 5*time.Minute) {
		t.Error("signature verified a tampered body")
	}
	if VerifyWebhook(secret, gotTS, gotSig, gotBody, fixed.Add(10*time.Minute), 5*time.Minute) {
		t.Error("stale timestamp should be rejected")
	}
}

func TestWebhookUnsignedWithoutSecret(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get(WebhookSignatureHeader)
	}))
	defer srv.Close()
	if err := (&webhookNotifier{url: srv.URL}).Notify(context.Background(), Fired{SearchName: "x"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if sig != "" {
		t.Errorf("unsigned webhook carried a signature: %q", sig)
	}
}
