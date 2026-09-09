package adminread

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Bu dosya, bir cihazın olaylarından cihaz-merkezli bir VARLIK GRAFI (entity graph)
// kurar: cihaz düğümü merkezde; olaylardan çıkarılan süreç, alan adı, uzak IP ve
// dosya varlıkları ona bağlanır. IR araştırması için ("bu cihaz neye dokundu?").
// Grafik kurma SAF ve testlidir.

// GraphNode, grafikteki bir varlıktır.
type GraphNode struct {
	ID    string `json:"id"`    // "type:value"
	Type  string `json:"type"`  // device | process | domain | ip | file
	Label string `json:"label"` // görüntü etiketi (varlık değeri)
}

// GraphEdge, cihaz ile bir varlık arasındaki ilişkidir.
type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`     // olay kategorisi (ran/connected/resolved/modified)
	Severity string `json:"severity"` // ilişkideki en yüksek önem
}

// EntityGraphDTO, cihaz-merkezli varlık grafiğidir.
type EntityGraphDTO struct {
	DeviceID string      `json:"device_id"`
	Nodes    []GraphNode `json:"nodes"`
	Edges    []GraphEdge `json:"edges"`
}

// entityFromEvent, bir olaydan (kategori + details) bir varlık düğümü çıkarır.
// Çıkarılamıyorsa ok=false. details, olayın yapısal ek verisidir.
func entityFromEvent(category string, details map[string]any) (typ, value string, ok bool) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, has := details[k]; has {
				if s, isStr := v.(string); isStr && strings.TrimSpace(s) != "" {
					return s
				}
			}
		}
		return ""
	}
	switch strings.ToUpper(category) {
	case "PROCESS":
		if v := get("process", "name", "image"); v != "" {
			return "process", v, true
		}
	case "NETWORK_CONN":
		if v := get("remote_ip", "ip", "remote"); v != "" {
			return "ip", v, true
		}
	case "NETWORK_DISCOVERY":
		if v := get("domain"); v != "" {
			return "domain", v, true
		}
		if v := get("mac", "ip"); v != "" {
			return "ip", v, true
		}
	case "SECURITY", "POLICY_VIOLATION":
		if v := get("domain"); v != "" {
			return "domain", v, true
		}
		if v := get("path"); v != "" {
			return "file", v, true
		}
		if v := get("remote_ip", "ip"); v != "" {
			return "ip", v, true
		}
	}
	return "", "", false
}

// edgeKind, düğüm türüne göre ilişki fiilini döner.
func edgeKind(typ string) string {
	switch typ {
	case "process":
		return "ran"
	case "ip":
		return "connected"
	case "domain":
		return "resolved"
	case "file":
		return "touched"
	default:
		return "related"
	}
}

// BuildEntityGraph, bir cihazın olaylarını cihaz-merkezli varlık grafiğine çevirir.
// SAF fonksiyon (test edilebilir). Aynı varlık tekilleştirilir; kenarda en yüksek
// önem tutulur.
func BuildEntityGraph(deviceID string, events []EventDTO) EntityGraphDTO {
	deviceNode := "device:" + deviceID
	g := EntityGraphDTO{
		DeviceID: deviceID,
		Nodes:    []GraphNode{{ID: deviceNode, Type: "device", Label: deviceID}},
	}
	nodeSeen := map[string]bool{deviceNode: true}
	edgeSev := map[string]string{} // edge "to" → en yüksek önem
	edgeKindByTo := map[string]string{}

	for _, e := range events {
		var details map[string]any
		if len(e.Details) > 0 {
			_ = json.Unmarshal(e.Details, &details)
		}
		typ, val, ok := entityFromEvent(e.Category, details)
		if !ok {
			continue
		}
		nodeID := typ + ":" + val
		if !nodeSeen[nodeID] {
			nodeSeen[nodeID] = true
			g.Nodes = append(g.Nodes, GraphNode{ID: nodeID, Type: typ, Label: val})
		}
		if sevRankValue(e.Severity) > sevRankValue(edgeSev[nodeID]) {
			edgeSev[nodeID] = strings.ToUpper(e.Severity)
		}
		edgeKindByTo[nodeID] = edgeKind(typ)
	}

	// Kenarları kararlı sırada üret (düğüm kimliğine göre).
	var tos []string
	for to := range edgeKindByTo {
		tos = append(tos, to)
	}
	sort.Strings(tos)
	for _, to := range tos {
		g.Edges = append(g.Edges, GraphEdge{
			From: deviceNode, To: to, Kind: edgeKindByTo[to], Severity: edgeSev[to],
		})
	}
	return g
}

// DeviceEntityGraph, bir cihazın son olaylarından varlık grafiğini oluşturur.
func (s *Service) DeviceEntityGraph(ctx context.Context, deviceID string, limit int) (EntityGraphDTO, error) {
	events, err := s.Events(ctx, deviceID, "", "", limit)
	if err != nil {
		return EntityGraphDTO{}, err
	}
	return BuildEntityGraph(deviceID, events), nil
}
