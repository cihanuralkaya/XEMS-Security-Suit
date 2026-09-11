package iam

import "testing"

func TestEngineEvaluate(t *testing.T) {
	policies := []Policy{
		{
			ID:     "p-allow-admin",
			Effect: EffectAllow,
			Match: []Condition{
				{Key: "subject.role", Op: OpEq, Value: "admin"},
			},
		},
		{
			ID:     "p-allow-same-tenant",
			Effect: EffectAllow,
			Match: []Condition{
				{Key: "subject.role", Op: OpIn, Value: "analyst, auditor"},
				{Key: "resource.tenant", Op: OpEq, Value: "acme"},
			},
		},
		{
			ID:     "p-deny-quarantine",
			Effect: EffectDeny,
			Match: []Condition{
				{Key: "subject.status", Op: OpEq, Value: "quarantined"},
			},
		},
		{
			ID:     "p-allow-read-public",
			Effect: EffectAllow,
			Match: []Condition{
				{Key: "resource.visibility", Op: OpPrefix, Value: "pub"},
			},
		},
	}
	eng := NewEngine(policies)

	tests := []struct {
		name        string
		req         Request
		wantAllowed bool
		wantPolicy  string
	}{
		{
			name:        "admin allowed",
			req:         Request{Subject: Attributes{"role": "admin"}, Action: "delete"},
			wantAllowed: true,
			wantPolicy:  "p-allow-admin",
		},
		{
			name: "analyst same tenant allowed (in + eq)",
			req: Request{
				Subject:  Attributes{"role": "analyst"},
				Resource: Attributes{"tenant": "acme"},
			},
			wantAllowed: true,
			wantPolicy:  "p-allow-same-tenant",
		},
		{
			name: "analyst wrong tenant default deny",
			req: Request{
				Subject:  Attributes{"role": "analyst"},
				Resource: Attributes{"tenant": "other"},
			},
			wantAllowed: false,
			wantPolicy:  "",
		},
		{
			name: "deny overrides allow",
			req: Request{
				Subject:  Attributes{"role": "admin", "status": "quarantined"},
				Resource: Attributes{"tenant": "acme"},
			},
			wantAllowed: false,
			wantPolicy:  "p-deny-quarantine",
		},
		{
			name:        "prefix match on resource",
			req:         Request{Resource: Attributes{"visibility": "public-web"}},
			wantAllowed: true,
			wantPolicy:  "p-allow-read-public",
		},
		{
			name:        "no match default deny",
			req:         Request{Subject: Attributes{"role": "guest"}},
			wantAllowed: false,
			wantPolicy:  "",
		},
		{
			name:        "missing attribute fails closed",
			req:         Request{Subject: Attributes{}},
			wantAllowed: false,
			wantPolicy:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, pol := eng.Evaluate(tt.req)
			if allowed != tt.wantAllowed || pol != tt.wantPolicy {
				t.Fatalf("Evaluate() = (%v, %q), want (%v, %q)",
					allowed, pol, tt.wantAllowed, tt.wantPolicy)
			}
		})
	}
}

func TestMatchCondition(t *testing.T) {
	req := Request{
		Subject:  Attributes{"role": "analyst", "dept": "soc-emea"},
		Resource: Attributes{"tenant": "acme", "path": "/reports/q4"},
	}
	tests := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq true", Condition{"subject.role", OpEq, "analyst"}, true},
		{"eq false", Condition{"subject.role", OpEq, "admin"}, false},
		{"ne true", Condition{"subject.role", OpNe, "admin"}, true},
		{"ne false", Condition{"subject.role", OpNe, "analyst"}, false},
		{"in true", Condition{"subject.role", OpIn, "admin,analyst"}, true},
		{"in false", Condition{"subject.role", OpIn, "admin,auditor"}, false},
		{"contains true", Condition{"resource.path", OpContains, "reports"}, true},
		{"contains false", Condition{"resource.path", OpContains, "logs"}, false},
		{"prefix true", Condition{"subject.dept", OpPrefix, "soc-"}, true},
		{"prefix false", Condition{"subject.dept", OpPrefix, "it-"}, false},
		{"missing key", Condition{"subject.missing", OpEq, ""}, false},
		{"missing key ne fails closed", Condition{"subject.missing", OpNe, "x"}, false},
		{"unknown namespace", Condition{"env.region", OpEq, "eu"}, false},
		{"unknown op", Condition{"subject.role", "regex", "an.*"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCondition(tt.cond, req); got != tt.want {
				t.Fatalf("matchCondition(%+v) = %v, want %v", tt.cond, got, tt.want)
			}
		})
	}
}

func TestEngineAddPolicyAndEmptyMatch(t *testing.T) {
	eng := NewEngine(nil)
	// Boş Match: catch-all allow.
	eng.AddPolicy(Policy{ID: "catch-all", Effect: EffectAllow})
	allowed, pol := eng.Evaluate(Request{Action: "anything"})
	if !allowed || pol != "catch-all" {
		t.Fatalf("catch-all allow = (%v, %q)", allowed, pol)
	}
	// Catch-all deny eklenince deny kazanır.
	eng.AddPolicy(Policy{ID: "catch-all-deny", Effect: EffectDeny})
	allowed, pol = eng.Evaluate(Request{Action: "anything"})
	if allowed || pol != "catch-all-deny" {
		t.Fatalf("deny overrides = (%v, %q)", allowed, pol)
	}
}

func TestNewEngineCopiesPolicies(t *testing.T) {
	src := []Policy{{ID: "p1", Effect: EffectAllow}}
	eng := NewEngine(src)
	src[0].ID = "mutated"
	if _, pol := eng.Evaluate(Request{}); pol != "p1" {
		t.Fatalf("engine should not observe caller mutation, got %q", pol)
	}
}
