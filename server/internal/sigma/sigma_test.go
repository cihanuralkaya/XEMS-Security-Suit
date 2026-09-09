package sigma

import "testing"

const singleSel = `
title: Suspicious Foo Process
id: abc-123
level: high
tags:
  - attack.t1059.001
detection:
  selection:
    Image: '\foo.exe'
    CommandLine: '-enc'
  condition: selection
`

func TestConvertSingleSelection(t *testing.T) {
	r, err := Convert([]byte(singleSel))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if r.ID != "sigma:abc-123" || r.Name != "Suspicious Foo Process" {
		t.Fatalf("kimlik/ad yanlış: %+v", r)
	}
	if r.Severity != "HIGH" {
		t.Fatalf("severity HIGH beklenirdi, %q", r.Severity)
	}
	if r.Fields["Image"] != `\foo.exe` || r.Fields["CommandLine"] != "-enc" {
		t.Fatalf("alanlar yanlış: %+v", r.Fields)
	}
	if r.Technique.ID != "T1059.001" {
		t.Fatalf("teknik T1059.001 beklenirdi, %q", r.Technique.ID)
	}
}

func TestConvertModifierAndMessage(t *testing.T) {
	doc := `
title: Msg Rule
level: medium
detection:
  sel:
    CommandLine|contains: mimikatz
    message: failed logon
  condition: sel
`
	r, err := Convert([]byte(doc))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if r.Fields["CommandLine"] != "mimikatz" {
		t.Fatalf("|contains alt-dizeye eşlenmeli, %+v", r.Fields)
	}
	// message alanı Contains'e gitmeli.
	if len(r.Contains) != 1 || r.Contains[0] != "failed logon" {
		t.Fatalf("message Contains'e eşlenmeli, %+v", r.Contains)
	}
}

func TestConvertAllOfThemMerges(t *testing.T) {
	doc := `
title: Merge
level: low
detection:
  sel1:
    A: x
  sel2:
    B: y
  condition: all of them
`
	r, err := Convert([]byte(doc))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if r.Fields["A"] != "x" || r.Fields["B"] != "y" {
		t.Fatalf("tüm seçimler AND ile birleşmeli, %+v", r.Fields)
	}
}

func TestConvertAndCondition(t *testing.T) {
	doc := `
title: AndCond
detection:
  a:
    F1: v1
  b:
    F2: v2
  condition: a and b
`
	r, err := Convert([]byte(doc))
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if r.Fields["F1"] != "v1" || r.Fields["F2"] != "v2" {
		t.Fatalf("a and b birleşmeli, %+v", r.Fields)
	}
	if r.Severity != "MEDIUM" {
		t.Fatalf("level yoksa MEDIUM varsayılmalı, %q", r.Severity)
	}
}

func TestConvertRejectsUnsupported(t *testing.T) {
	cases := map[string]string{
		"or": `
title: T
detection:
  selection:
    A: x
  filter:
    B: y
  condition: selection or filter
`,
		"not": `
title: T
detection:
  selection:
    A: x
  filter:
    B: y
  condition: selection and not filter
`,
		"1of": `
title: T
detection:
  selection:
    A: x
  condition: 1 of them
`,
		"list-value": `
title: T
detection:
  selection:
    A:
      - x
      - y
  condition: selection
`,
		"no-detection": `
title: T
level: high
`,
	}
	for name, doc := range cases {
		if _, err := Convert([]byte(doc)); err == nil {
			t.Fatalf("%s: hata beklenirdi", name)
		}
	}
}

func TestConvertMultiCollectsSkips(t *testing.T) {
	multi := singleSel + "\n---\n" + `
title: Bad
detection:
  selection:
    A:
      - x
      - y
  condition: selection
` + "\n---\n" + `
title: Good2
level: low
detection:
  sel:
    Field: val
  condition: sel
`
	rules, skips, err := ConvertMulti([]byte(multi))
	if err != nil {
		t.Fatalf("ConvertMulti: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("2 geçerli kural beklenirdi, %d (%+v)", len(rules), rules)
	}
	if len(skips) != 1 {
		t.Fatalf("1 atlanan belge beklenirdi, %v", skips)
	}
}

func TestConvertedRulesPassEngineValidation(t *testing.T) {
	// Çevrilen kurallar detect motorunun doğrulamasından geçmeli (ID/Name/Severity).
	rules, _, _ := ConvertMulti([]byte(singleSel))
	if len(rules) != 1 {
		t.Fatalf("1 kural beklenirdi")
	}
	r := rules[0]
	if r.ID == "" || r.Name == "" || r.Severity == "" {
		t.Fatalf("motor doğrulaması için ID/Name/Severity dolu olmalı: %+v", r)
	}
}
