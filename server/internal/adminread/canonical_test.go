package adminread

import (
	"encoding/json"
	"testing"

	"xems.corp/suite/server/internal/model"
)

// TestNewEventDTOPromotesCanonical, details JSON'undaki kanonik anahtarların DTO'ya
// ilk-sınıf alan olarak yükseltildiğini ve şema sürümünün daima damgalandığını doğrular.
func TestNewEventDTOPromotesCanonical(t *testing.T) {
	details, _ := json.Marshal(map[string]any{
		"source":          "winlog",
		"event_type":      "winevent_4625",
		"correlation_id":  "cor_abc",
		"parent_event_id": "evt_parent",
		"confidence":      0.85,
		"src_ip":          "1.2.3.4",
	})
	dto := newEventDTO(EventRow{ID: "row-1", Severity: "HIGH", Details: details})

	if dto.SchemaVersion != model.EventSchemaVersion {
		t.Errorf("schema_version damgalanmalı: %q", dto.SchemaVersion)
	}
	if dto.Source != "winlog" || dto.EventType != "winevent_4625" {
		t.Errorf("source/event_type yükseltilmeli: %+v", dto)
	}
	if dto.CorrelationID != "cor_abc" || dto.ParentEventID != "evt_parent" {
		t.Errorf("korelasyon/parent yükseltilmeli: %+v", dto)
	}
	if dto.Confidence != 0.85 {
		t.Errorf("confidence yükseltilmeli: %v", dto.Confidence)
	}
	// Ham details korunmalı (yükseltme yıkıcı değil).
	if len(dto.Details) == 0 {
		t.Error("ham details korunmalı")
	}
}

// TestNewEventDTONoDetails, details yokken yalnız schema_version'ın set edildiğini ve
// diğer kanonik alanların boş (omitempty) kaldığını doğrular.
func TestNewEventDTONoDetails(t *testing.T) {
	dto := newEventDTO(EventRow{ID: "row-2", Severity: "INFO"})
	if dto.SchemaVersion != model.EventSchemaVersion {
		t.Error("schema_version details olmadan da damgalanmalı")
	}
	if dto.Source != "" || dto.CorrelationID != "" || dto.Confidence != 0 {
		t.Errorf("details yokken kanonik alanlar boş kalmalı: %+v", dto)
	}
}
