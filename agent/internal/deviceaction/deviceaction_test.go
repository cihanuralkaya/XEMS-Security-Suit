package deviceaction

import "testing"

// UYARI: Wipe() ARTIK GERÇEK kripto-silme yapar (BitLocker/LUKS anahtar imhası).
// Bu test Wipe()'ı ASLA çağırmaz — yalnız ARM kapısını (WipeArmed) doğrular.
// Gerçek silme davranışı yalnız derleme + kod incelemesiyle doğrulanır, çalıştırılmaz.

// WipeArmed, güvenli varsayılan: XEMS_ALLOW_WIPE ayarlı değilken ajan silmeye
// ARM'lı OLMAMALI. Bu, kazara veri kaybını önleyen üçüncü güvenlik katmanıdır.
func TestWipeArmedDefaultsOff(t *testing.T) {
	t.Setenv("XEMS_ALLOW_WIPE", "") // açıkça boş
	if WipeArmed() {
		t.Fatal("XEMS_ALLOW_WIPE boşken ajan silmeye ARM'lı OLMAMALI (güvenli varsayılan)")
	}
}

// XEMS_ALLOW_WIPE=1 açıkça ayarlandığında ARM'lı olmalı; diğer değerler ARM'lamaz.
func TestWipeArmedOnlyWithExactFlag(t *testing.T) {
	t.Setenv("XEMS_ALLOW_WIPE", "1")
	if !WipeArmed() {
		t.Fatal("XEMS_ALLOW_WIPE=1 iken ARM'lı olmalı")
	}
	for _, v := range []string{"0", "true", "yes", "2", " 1"} {
		t.Setenv("XEMS_ALLOW_WIPE", v)
		if WipeArmed() {
			t.Fatalf("XEMS_ALLOW_WIPE=%q ARM'lamamalı (yalnız tam '1')", v)
		}
	}
}
