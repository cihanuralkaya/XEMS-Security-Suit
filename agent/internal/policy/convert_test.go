package policy

import (
	"testing"
	"time"

	xemsv1 "xems.corp/suite/gen/xems/v1"
)

func TestFromProtoMapsRules(t *testing.T) {
	pb := &xemsv1.PolicyBundle{
		PolicyVersion: "v42",
		Rules: []*xemsv1.PolicyRule{
			{
				RuleId:      "r1",
				Type:        xemsv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK,
				TargetValue: "game.exe",
				StartTime:   "18:00",
				EndTime:     "08:00",
				ActiveDays:  []uint32{1, 2, 3, 4, 5},
			},
			{
				RuleId:      "r2",
				Type:        xemsv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS,
				TargetValue: "torrent.exe",
			},
		},
	}
	b := FromProto(pb)
	if b.Version != "v42" || len(b.Rules) != 2 {
		t.Fatalf("beklenmeyen bundle: %+v", b)
	}

	// Dönüştürülen kural gerçekten motorda çalışmalı: Cuma 20:00 game.exe yasak.
	e := New(b)
	fri := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	if !e.EvaluateProcess("game.exe", fri).Blocked {
		t.Error("dönüştürülen zaman-bloğu kuralı uygulanmadı")
	}
	if b.Rules[0].Start != 1080 || b.Rules[0].End != 480 {
		t.Errorf("saat ayrıştırma yanlış: start=%d end=%d", b.Rules[0].Start, b.Rules[0].End)
	}
	if b.Rules[1].Type != RuleAppBlockAlways {
		t.Error("her-zaman-yasak tipi eşlenmedi")
	}
	// active_days doğru eşlendi mi (Pzt-Cum)?
	if !b.Rules[0].ActiveDays[int(time.Monday)] || b.Rules[0].ActiveDays[int(time.Sunday)] {
		t.Error("active_days yanlış eşlendi")
	}
}

func TestFromProtoNil(t *testing.T) {
	if b := FromProto(nil); b.Version != "" || len(b.Rules) != 0 {
		t.Fatal("nil bundle boş dönmeliydi")
	}
}
