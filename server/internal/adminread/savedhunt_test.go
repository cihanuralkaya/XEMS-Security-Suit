package adminread

import (
	"testing"
	"time"
)

func TestParseSavedFilter(t *testing.T) {
	since := time.Unix(1_700_000_000, 0)
	f, err := parseSavedFilter(`{"mode":"query","category":"SECURITY","severity":"HIGH","message_contains":"mimikatz","device_id":"d1","limit":50,"since":"2020-01-01T00:00:00Z"}`, since)
	if err != nil {
		t.Fatalf("parseSavedFilter: %v", err)
	}
	if f.Category != "SECURITY" || f.Severity != "HIGH" || f.MessageContains != "mimikatz" || f.DeviceID != "d1" || f.Limit != 50 {
		t.Fatalf("alanlar yanlış: %+v", f)
	}
	// Since ZORUNLU override edilmeli (kayıtlı aramanın since'i yok sayılır).
	if !f.Since.Equal(since) {
		t.Fatalf("Since override edilmeli, %v", f.Since)
	}
}

func TestParseSavedFilterBadJSON(t *testing.T) {
	if _, err := parseSavedFilter("not json", time.Now()); err == nil {
		t.Fatal("bozuk JSON hata döndürmeli")
	}
}
