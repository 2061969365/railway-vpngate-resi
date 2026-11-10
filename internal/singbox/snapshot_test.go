package singbox

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

type snapshotRow struct {
	host    string
	port    int
	speed   int64
	country string
	short   string
	config  string
}

func profileFor(host string, port int) string {
	return fmt.Sprintf("client\nproto tcp-client\nremote %s %d tcp\n<ca>\nQ0E=\n</ca>\n", host, port)
}

func buildCSV(rows []snapshotRow) string {
	var builder strings.Builder
	builder.WriteString("#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,OpenVPN_ConfigData_Base64\n")
	for _, row := range rows {
		config := row.config
		if config == "" {
			config = profileFor(row.host, row.port)
		}
		fmt.Fprintf(&builder, "h-%s,203.0.113.1,0,0,%d,%s,%s,%s\n",
			row.host, row.speed, row.country, row.short,
			base64.StdEncoding.EncodeToString([]byte(config)))
	}
	return builder.String()
}

func defaultRows() []snapshotRow {
	return []snapshotRow{
		{host: "198.51.100.1", port: 443, speed: 1000, country: "Japan", short: "jp"},
		{host: "198.51.100.2", port: 443, speed: 3000, country: "Korea", short: "kr"},
		{host: "198.51.100.3", port: 443, speed: 2000, country: "United States", short: "us"},
	}
}

func TestParseSnapshot(t *testing.T) {
	candidates, err := ParseSnapshot(buildCSV(defaultRows()), SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 {
		t.Fatalf("candidates = %d", len(candidates))
	}
	if candidates[0].Country != "Japan" || candidates[0].CountryShort != "JP" {
		t.Fatalf("first candidate = %#v", candidates[0])
	}
	if candidates[1].Speed != 3000 {
		t.Fatalf("second speed = %d", candidates[1].Speed)
	}
	if candidates[0].Endpoint.Tag != "" {
		t.Fatalf("endpoint tag = %q", candidates[0].Endpoint.Tag)
	}
}

func TestSnapshotToNodesRanksBySpeed(t *testing.T) {
	nodes, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{Limit: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	order := []string{"198.51.100.2", "198.51.100.3", "198.51.100.1"}
	for index, host := range order {
		if nodes[index].Server != host {
			t.Fatalf("node %d server = %q, want %q", index, nodes[index].Server, host)
		}
		if nodes[index].LatencyMS != nil {
			t.Fatalf("node %d latency = %v", index, nodes[index].LatencyMS)
		}
	}
}

func TestSnapshotStableSortAndLimit(t *testing.T) {
	rows := []snapshotRow{
		{host: "198.51.100.1", port: 443, speed: 1000, country: "A", short: "a"},
		{host: "198.51.100.2", port: 443, speed: 1000, country: "B", short: "b"},
		{host: "198.51.100.3", port: 443, speed: 1000, country: "C", short: "c"},
	}
	nodes, err := SnapshotToNodes(buildCSV(rows), SnapshotOptions{Limit: 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Server != "198.51.100.1" || nodes[1].Server != "198.51.100.2" {
		t.Fatalf("stable order = %q/%q", nodes[0].Server, nodes[1].Server)
	}
}

func TestSnapshotLimitAppliesAfterFullRanking(t *testing.T) {
	rows := []snapshotRow{
		{host: "198.51.100.1", port: 443, speed: 1000, country: "A", short: "a"},
		{host: "198.51.100.2", port: 443, speed: 3000, country: "B", short: "b"},
		{host: "198.51.100.3", port: 443, speed: 2000, country: "C", short: "c"},
	}
	nodes, err := SnapshotToNodes(buildCSV(rows), SnapshotOptions{Limit: 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].Server != "198.51.100.2" || nodes[1].Server != "198.51.100.3" {
		t.Fatalf("limit must keep the global top-2, got %#v", nodes)
	}
}

func TestSnapshotLineCountMatchesPythonSplitlines(t *testing.T) {
	if got := snapshotLineCount("a\nb\r\nc\rd\u2028e\u2029f"); got != 6 {
		t.Fatalf("line count = %d, want 6", got)
	}
	if got := snapshotLineCount("a\n"); got != 1 {
		t.Fatalf("trailing newline count = %d, want 1", got)
	}
	lines := splitSnapshotLines("a\r\nb\rc\nd")
	want := []string{"a", "b", "c", "d"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %#v", lines)
	}
	for index := range want {
		if lines[index] != want[index] {
			t.Fatalf("lines = %#v", lines)
		}
	}
	if trailing := splitSnapshotLines("a\n"); len(trailing) != 1 || trailing[0] != "a" {
		t.Fatalf("trailing separator lines = %#v", trailing)
	}
	if empty := splitSnapshotLines("\n"); len(empty) != 1 || empty[0] != "" {
		t.Fatalf("empty line split = %#v", empty)
	}
}

func TestSnapshotProbeChunkStopsAfterSurvivors(t *testing.T) {
	probe := func(host string, port int) int64 {
		switch host {
		case "198.51.100.2":
			return 0
		case "198.51.100.3":
			return 20
		default:
			return 99
		}
	}
	nodes, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{
		Probe: true, ProbePool: 1, ProbeWorkers: 2,
	}, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Server != "198.51.100.3" {
		t.Fatalf("nodes = %#v", nodes)
	}
	if nodes[0].LatencyMS == nil || *nodes[0].LatencyMS != 20 {
		t.Fatalf("latency = %v", nodes[0].LatencyMS)
	}
}

func TestSnapshotProbeFallsOverToSecondRemote(t *testing.T) {
	config := "client\nproto tcp-client\nremote 198.51.100.9 443 tcp\nremote 198.51.100.8 8443 tcp\n<ca>\nQ0E=\n</ca>\n"
	rows := []snapshotRow{{host: "198.51.100.9", port: 443, speed: 100, config: config}}
	probe := func(host string, port int) int64 {
		if host == "198.51.100.8" {
			return 30
		}
		return 0
	}
	nodes, err := SnapshotToNodes(buildCSV(rows), SnapshotOptions{
		Probe: true, ProbePool: 30, ProbeWorkers: 2,
	}, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %#v", nodes)
	}
	if nodes[0].LatencyMS == nil || *nodes[0].LatencyMS != 30 {
		t.Fatalf("latency = %v", nodes[0].LatencyMS)
	}
}

func TestSnapshotAllDead(t *testing.T) {
	probe := func(string, int) int64 { return 0 }
	nodes, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{
		Probe: true, ProbePool: 30, ProbeWorkers: 2,
	}, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes = %#v", nodes)
	}
	if _, err := SnapshotToEndpoints(buildCSV(defaultRows()), SnapshotOptions{
		Probe: true, ProbePool: 30, ProbeWorkers: 2,
	}, probe, nil, "vpngate"); err == nil {
		t.Fatal("expected error for no reachable nodes")
	}
}

func TestSnapshotRealTopK(t *testing.T) {
	dial := func(endpoint Endpoint) *int64 {
		host, _ := PrimaryServer(endpoint)
		switch host {
		case "198.51.100.2":
			return Int64(80)
		case "198.51.100.3":
			return Int64(10)
		default:
			return nil
		}
	}
	nodes, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{
		RealTopK: 2, DialWorkers: 2,
	}, nil, dial)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Server != "198.51.100.3" || nodes[1].Server != "198.51.100.2" {
		t.Fatalf("real order = %q/%q", nodes[0].Server, nodes[1].Server)
	}
	if nodes[2].RealLatencyMS != nil {
		t.Fatalf("unmeasured real latency = %v", nodes[2].RealLatencyMS)
	}
}

func TestSnapshotSkipDialKeys(t *testing.T) {
	var dialed []string
	dial := func(endpoint Endpoint) *int64 {
		host, _ := PrimaryServer(endpoint)
		dialed = append(dialed, host)
		return Int64(50)
	}
	skip := map[string]struct{}{"198.51.100.2:443": {}}
	if _, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{
		RealTopK: 1, DialWorkers: 1, SkipDialKeys: skip,
	}, nil, dial); err != nil {
		t.Fatal(err)
	}
	for _, host := range dialed {
		if host == "198.51.100.2" {
			t.Fatal("skip_dial_keys node was dialed")
		}
	}
}

func TestSnapshotRejectsBadInput(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := ParseSnapshot("", SnapshotOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing column", func(t *testing.T) {
		if _, err := ParseSnapshot("HostName,Speed\nx,1\n", SnapshotOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("no convertible rows", func(t *testing.T) {
		csv := "HostName,OpenVPN_ConfigData_Base64\nx,not-base64\n"
		if _, err := ParseSnapshot(csv, SnapshotOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("line limit", func(t *testing.T) {
		csv := strings.Repeat("*\n", MaxSnapshotLines+1)
		if _, err := ParseSnapshot(csv, SnapshotOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("size limit", func(t *testing.T) {
		csv := strings.Repeat("x", MaxSnapshotBytes+1)
		if _, err := ParseSnapshot(csv, SnapshotOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("negative limits", func(t *testing.T) {
		if _, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{ProbePool: -1}, nil, nil); err == nil {
			t.Fatal("expected probe_pool error")
		}
		if _, err := SnapshotToNodes(buildCSV(defaultRows()), SnapshotOptions{Limit: -1}, nil, nil); err == nil {
			t.Fatal("expected limit error")
		}
	})
}

func TestSnapshotSkipsBadRowsButKeepsGoodOnes(t *testing.T) {
	csv := buildCSV([]snapshotRow{{host: "198.51.100.1", port: 443, speed: 10}})
	csv = strings.TrimSuffix(csv, "\n") + "\nbad,1,0,0,5,Nowhere,ZZ,@@@\n"
	candidates, err := ParseSnapshot(csv, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d", len(candidates))
	}
}

func FuzzParseSnapshot(f *testing.F) {
	f.Add(buildCSV(defaultRows()))
	f.Add("HostName,OpenVPN_ConfigData_Base64\n")
	f.Add("#HostName,Speed\n*skip\n")
	f.Fuzz(func(t *testing.T, csv string) {
		_, _ = ParseSnapshot(csv, SnapshotOptions{AllowPrivateRemotes: true})
	})
}
