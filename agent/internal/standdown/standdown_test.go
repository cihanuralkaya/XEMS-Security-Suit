package standdown

import (
	"testing"
)

func TestWriteAndExists(t *testing.T) {
	dir := t.TempDir()
	if Exists(dir) {
		t.Fatal("başlangıçta işaret olmamalı")
	}
	if err := Write(dir, "dev-1", "signed offboard token"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !Exists(dir) {
		t.Fatal("Write sonrası işaret var olmalı")
	}
	// İdempotent: ikinci yazım hata vermemeli.
	if err := Write(dir, "dev-1", "again"); err != nil {
		t.Fatalf("ikinci Write: %v", err)
	}
}

func TestExistsMissingDir(t *testing.T) {
	if Exists(t.TempDir() + "/nope") {
		t.Fatal("olmayan dizinde işaret raporlanmamalı")
	}
}
