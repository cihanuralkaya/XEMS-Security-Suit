package policy

import xemsv1 "xems.corp/suite/gen/xems/v1"

// FromProto, sunucudan gelen proto PolicyBundle'ı motor domain Bundle'ına
// çevirir. Bu dosya, engine.go'yu proto'dan bağımsız tutmak için ayrıdır:
// dönüşüm burada, değerlendirme mantığı orada.
func FromProto(pb *xemsv1.PolicyBundle) Bundle {
	if pb == nil {
		return Bundle{}
	}
	b := Bundle{Version: pb.GetPolicyVersion()}
	for _, pr := range pb.GetRules() {
		r := Rule{
			ID:     pr.GetRuleId(),
			Type:   ruleTypeFromProto(pr.GetType()),
			Target: pr.GetTargetValue(),
		}
		if s, ok := ParseHHMM(pr.GetStartTime()); ok {
			r.Start = s
		}
		if e, ok := ParseHHMM(pr.GetEndTime()); ok {
			r.End = e
		}
		for _, d := range pr.GetActiveDays() {
			if d <= 6 {
				r.ActiveDays[d] = true
			}
		}
		b.Rules = append(b.Rules, r)
	}
	return b
}

func ruleTypeFromProto(t xemsv1.PolicyRule_RuleType) RuleType {
	switch t {
	case xemsv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK:
		return RuleAppTimeBlock
	case xemsv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS:
		return RuleAppBlockAlways
	case xemsv1.PolicyRule_RULE_TYPE_NETWORK_RULE:
		return RuleNetwork
	default:
		return RuleUnspecified
	}
}
