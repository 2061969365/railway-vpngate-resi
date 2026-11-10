package singbox

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// MaxSnapshotBytes caps one VPNGate CSV snapshot.
	MaxSnapshotBytes = 8 << 20
	// MaxSnapshotLines caps the raw line count of one snapshot.
	MaxSnapshotLines = 5000
)

// TCPProbe returns handshake latency in milliseconds, 0 when unreachable.
type TCPProbe func(host string, port int) int64

// DialFunc performs one real tunnel dial and returns end-to-end latency.
type DialFunc func(endpoint Endpoint) *int64

// Candidate is one parsed but unranked snapshot row.
type Candidate struct {
	Speed        int64
	Country      string
	CountryShort string
	Endpoint     Endpoint
}

// SnapshotOptions mirrors snapshot_to_nodes' arguments that affect the pure
// ranking/pipeline. Timeouts live in the injected probe/dial functions.
type SnapshotOptions struct {
	Limit               int
	Probe               bool
	ProbePool           int
	ProbeWorkers        int
	RealTopK            int
	DialWorkers         int
	SkipDialKeys        map[string]struct{}
	Username            string
	Password            string
	AllowPrivateRemotes bool
	ResolveHost         HostResolver
}

// ParseSnapshot parses a VPNGate CSV snapshot into candidates. It enforces the
// size/line caps and skips UDP-only, broken or unsafe rows exactly like
// _iter_tcp_candidates.
func ParseSnapshot(csvText string, opts SnapshotOptions) ([]Candidate, error) {
	if len(csvText) > MaxSnapshotBytes {
		return nil, fmt.Errorf("snapshot exceeds %d bytes", MaxSnapshotBytes)
	}
	if rows := snapshotLineCount(csvText); rows > MaxSnapshotLines {
		return nil, fmt.Errorf("snapshot exceeds %d rows", MaxSnapshotLines)
	}
	lines := make([]string, 0, 64)
	for _, line := range splitSnapshotLines(csvText) {
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty snapshot")
	}
	if strings.HasPrefix(lines[0], "#") {
		lines[0] = lines[0][1:]
	}

	reader := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read snapshot header: %w", err)
	}
	column := make(map[string]int, len(header))
	for index, name := range header {
		column[name] = index
	}
	encodedIndex, ok := column["OpenVPN_ConfigData_Base64"]
	if !ok {
		return nil, fmt.Errorf("snapshot columns are incomplete")
	}
	countryIndex := columnIndex(column, "CountryLong")
	shortIndex := columnIndex(column, "CountryShort")
	speedIndex := columnIndex(column, "Speed")

	username := opts.Username
	if username == "" {
		username = DefaultUsername
	}
	password := opts.Password
	if password == "" {
		password = DefaultPassword
	}
	candidates := make([]Candidate, 0, 64)
	found := false
	for {
		row, readErr := reader.Read()
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			// Python's csv module raises on a malformed row; a malformed row
			// in a third-party snapshot is skipped instead of failing all.
			continue
		}
		encoded := strings.TrimSpace(field(row, encodedIndex))
		if encoded == "" {
			continue
		}
		if len(encoded) > (MaxConfigBytes*4/3)+8 {
			continue
		}
		if strings.ContainsAny(encoded, " \t\r\n") {
			continue
		}
		raw, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil || len(raw) > MaxConfigBytes || !utf8.Valid(raw) {
			continue
		}
		endpoint, parseErr := ParseOVPN(string(raw), ParseOptions{
			Tag:                 "",
			Username:            username,
			Password:            password,
			OnDemand:            true,
			AllowPrivateRemotes: opts.AllowPrivateRemotes,
			ResolveHost:         opts.ResolveHost,
		})
		if parseErr != nil {
			continue
		}
		speed := int64(0)
		if text := strings.TrimSpace(field(row, speedIndex)); text != "" {
			if parsed, speedErr := strconv.ParseInt(strings.ReplaceAll(text, "_", ""), 10, 64); speedErr == nil {
				speed = parsed
			}
		}
		candidates = append(candidates, Candidate{
			Speed:        speed,
			Country:      strings.TrimSpace(field(row, countryIndex)),
			CountryShort: strings.ToUpper(strings.TrimSpace(field(row, shortIndex))),
			Endpoint:     endpoint,
		})
		found = true
	}
	if !found {
		return nil, fmt.Errorf("snapshot contains no TCP-convertible nodes")
	}
	return candidates, nil
}

// SnapshotToNodes ranks candidates and optionally probes them.
func SnapshotToNodes(csvText string, opts SnapshotOptions, probe TCPProbe, dial DialFunc) ([]Node, error) {
	if opts.ProbePool < 0 {
		return nil, fmt.Errorf("probe_pool must be >= 0, got %d", opts.ProbePool)
	}
	if opts.Limit < 0 {
		return nil, fmt.Errorf("limit must be >= 0, got %d", opts.Limit)
	}
	candidates, err := ParseSnapshot(csvText, opts)
	if err != nil {
		return nil, err
	}
	ranked := append([]Candidate(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Speed > ranked[j].Speed })

	nodes := make([]Node, 0, len(ranked))
	if !opts.Probe {
		for _, candidate := range ranked {
			nodes = append(nodes, nodeFor(candidate, nil))
		}
	} else {
		if probe == nil {
			return nil, fmt.Errorf("probe function is required when probe is enabled")
		}
		step := opts.ProbePool
		if step <= 0 {
			step = len(ranked)
		}
		if step <= 0 {
			step = 1
		}
		for start := 0; start < len(ranked); start += step {
			end := start + step
			if end > len(ranked) {
				end = len(ranked)
			}
			chunk := ranked[start:end]
			latencies := probeChunk(chunk, opts.ProbeWorkers, probe)
			alive := make([]struct {
				latency int64
				item    Candidate
			}, 0, len(chunk))
			for index, candidate := range chunk {
				if latencies[index] > 0 {
					alive = append(alive, struct {
						latency int64
						item    Candidate
					}{latencies[index], candidate})
				}
			}
			sort.SliceStable(alive, func(i, j int) bool { return alive[i].latency < alive[j].latency })
			for _, entry := range alive {
				nodes = append(nodes, nodeFor(entry.item, Int64(entry.latency)))
			}
			if len(nodes) > 0 {
				break
			}
		}
	}

	if opts.RealTopK > 0 && len(nodes) > 0 {
		if dial == nil {
			return nil, fmt.Errorf("dial function is required when real_topk is enabled")
		}
		applyRealLatency(nodes, opts, dial)
	}
	if opts.Limit > 0 && len(nodes) > opts.Limit {
		nodes = nodes[:opts.Limit]
	}
	return nodes, nil
}

// SnapshotToEndpoints parses, ranks and tags in one call. It mirrors
// snapshot_to_endpoints: no reachable nodes is an error.
func SnapshotToEndpoints(csvText string, opts SnapshotOptions, probe TCPProbe, dial DialFunc, tagPrefix string) ([]Endpoint, error) {
	nodes, err := SnapshotToNodes(csvText, opts, probe, dial)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("snapshot contains no reachable nodes")
	}
	return NodesToEndpoints(nodes, tagPrefix), nil
}

// ProbeEndpointLatency returns the first live remote's handshake latency.
func ProbeEndpointLatency(endpoint Endpoint, probe TCPProbe) int64 {
	if probe == nil {
		return 0
	}
	for _, remote := range EndpointRemotes(endpoint) {
		if latency := probe(remote.Host, remote.Port); latency > 0 {
			return latency
		}
	}
	return 0
}

func nodeFor(candidate Candidate, latency *int64) Node {
	host, port := PrimaryServer(candidate.Endpoint)
	return Node{
		Server:        host,
		ServerPort:    port,
		Country:       candidate.Country,
		CountryShort:  candidate.CountryShort,
		Speed:         candidate.Speed,
		LatencyMS:     latency,
		RealLatencyMS: nil,
		Endpoint:      candidate.Endpoint,
	}
}

func probeChunk(chunk []Candidate, workers int, probe TCPProbe) []int64 {
	latencies := make([]int64, len(chunk))
	if len(chunk) == 0 {
		return latencies
	}
	if workers < 1 {
		workers = 1
	}
	slots := make(chan struct{}, workers)
	var wait sync.WaitGroup
	for index := range chunk {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			latencies[index] = ProbeEndpointLatency(chunk[index].Endpoint, probe)
		}(index)
	}
	wait.Wait()
	return latencies
}

func applyRealLatency(nodes []Node, opts SnapshotOptions, dial DialFunc) {
	workers := opts.DialWorkers
	if workers < 1 {
		workers = 1
	}
	skip := opts.SkipDialKeys
	target := opts.RealTopK
	if target > len(nodes) {
		target = len(nodes)
	}
	index := 0
	measured := 0
	for measured < target && index < len(nodes) {
		batch := make([]int, 0, target-measured)
		for len(batch) == 0 && index < len(nodes) {
			size := target - measured
			if size < 1 {
				size = 1
			}
			end := index + size
			if end > len(nodes) {
				end = len(nodes)
			}
			for cursor := index; cursor < end; cursor++ {
				key := nodes[cursor].Server + ":" + strconv.Itoa(nodes[cursor].ServerPort)
				if _, skipped := skip[key]; skipped {
					continue
				}
				batch = append(batch, cursor)
			}
			index = end
		}
		if len(batch) == 0 {
			break
		}
		dialBatch(nodes, batch, workers, dial)
		measured = 0
		for cursor := 0; cursor < index; cursor++ {
			if nodes[cursor].RealLatencyMS != nil {
				measured++
			}
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		left, right := nodes[i], nodes[j]
		if left.RealLatencyMS != nil || right.RealLatencyMS != nil {
			if left.RealLatencyMS == nil {
				return false
			}
			if right.RealLatencyMS == nil {
				return true
			}
			return *left.RealLatencyMS < *right.RealLatencyMS
		}
		leftLatency := int64(math.MaxInt64)
		if left.LatencyMS != nil {
			leftLatency = *left.LatencyMS
		}
		rightLatency := int64(math.MaxInt64)
		if right.LatencyMS != nil {
			rightLatency = *right.LatencyMS
		}
		return leftLatency < rightLatency
	})
}

func dialBatch(nodes []Node, batch []int, workers int, dial DialFunc) {
	slots := make(chan struct{}, workers)
	var wait sync.WaitGroup
	for _, nodeIndex := range batch {
		wait.Add(1)
		go func(nodeIndex int) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			result := dial(nodes[nodeIndex].Endpoint)
			if result != nil && *result > 0 {
				nodes[nodeIndex].RealLatencyMS = result
			}
		}(nodeIndex)
	}
	wait.Wait()
}

func field(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return row[index]
}

func columnIndex(columns map[string]int, name string) int {
	if index, ok := columns[name]; ok {
		return index
	}
	return -1
}

// snapshotLineCount mirrors Python's _check_snapshot_limits/splitlines line
// count for every separator Python treats as a boundary.
func snapshotLineCount(text string) int {
	lines := 0
	lastEnd := 0
	for index := 0; index < len(text); {
		r, size := utf8.DecodeRuneInString(text[index:])
		switch r {
		case '\r':
			lines++
			index += size
			if index < len(text) && text[index] == '\n' {
				index++
			}
			lastEnd = index
			continue
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			lines++
			index += size
			lastEnd = index
			continue
		}
		index += size
	}
	if lastEnd < len(text) {
		lines++
	}
	return lines
}

// splitSnapshotLines mirrors Python's str.splitlines for CSV rows.
func splitSnapshotLines(text string) []string {
	lines := make([]string, 0, 64)
	start := 0
	for index := 0; index < len(text); {
		r, size := utf8.DecodeRuneInString(text[index:])
		switch r {
		case '\r':
			lines = append(lines, text[start:index])
			index += size
			if index < len(text) && text[index] == '\n' {
				index++
			}
			start = index
			continue
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			lines = append(lines, text[start:index])
			index += size
			start = index
			continue
		}
		index += size
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}
