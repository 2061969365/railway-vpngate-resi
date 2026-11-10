// Package contract replays Python-generated golden fixtures against the Go
// port. The fixtures live in tests/contract/golden and are produced by
// scripts/gen_golden.py; comparisons are semantic (JSON object key order is
// irrelevant, array order is preserved).
package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

type goldenParse struct {
	Tag                 string `json:"tag"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	OnDemand            bool   `json:"on_demand"`
	AllowPrivateRemotes bool   `json:"allow_private_remotes"`
}

type goldenOptions struct {
	MixedListen     string                `json:"mixed_listen"`
	MixedPort       int                   `json:"mixed_port"`
	MixedUsers      [][2]string           `json:"mixed_users"`
	Final           string                `json:"final"`
	Preferred       string                `json:"preferred"`
	Backup          string                `json:"backup"`
	VLESSUUID       *string               `json:"vless_uuid"`
	VLESSDirectPort int                   `json:"vless_direct_port"`
	VLESSDirectPath string                `json:"vless_direct_path"`
	VLESSChainPort  int                   `json:"vless_chain_port"`
	VLESSChainPath  string                `json:"vless_chain_path"`
	Resi            *singbox.ResiOutbound `json:"resi"`
	ResiPort        int                   `json:"resi_port"`
	ResiPath        string                `json:"resi_path"`
	ResiInPort      int                   `json:"resi_in_port"`
	ResiRotate      bool                  `json:"resi_rotate"`
	ResiRotateBase  int                   `json:"resi_rotate_base"`
	ResiRotateTags  *[]string             `json:"resi_rotate_tags"`
	ChainCandidates *[]string             `json:"chain_candidates"`
	ClashAPI        *singbox.ClashAPI     `json:"clash_api"`
	PersistentTags  []string              `json:"persistent_tags"`
}

type goldenCase struct {
	Name      string             `json:"name"`
	Kind      string             `json:"kind"`
	OVPN      string             `json:"ovpn"`
	Parse     *goldenParse       `json:"parse"`
	Expected  json.RawMessage    `json:"expected"`
	Endpoints []singbox.Endpoint `json:"endpoints"`
	Options   *goldenOptions     `json:"options"`
	Old       []singbox.Node     `json:"old"`
	New       []singbox.Node     `json:"new"`
	Prefix    string             `json:"prefix"`
	CSV       string             `json:"csv"`
	Limit     int                `json:"limit"`
	// ErrorContains is used by ovpn_error/config_error/remote_policy cases.
	ErrorContains string `json:"error_contains"`
	// ProbeLats drives snapshot_probe cases: host -> handshake ms (0 = dead).
	ProbeLats    map[string]int64 `json:"probe_lats"`
	ProbePool    int              `json:"probe_pool"`
	ProbeWorkers int              `json:"probe_workers"`
	Host         string           `json:"host"`
	Port         int              `json:"port"`
	AllowPrivate bool             `json:"allow_private"`
}

func TestGoldenFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("golden", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no golden fixtures found; run python scripts/gen_golden.py")
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var testCase goldenCase
		if err := json.Unmarshal(raw, &testCase); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		name := testCase.Name
		if name == "" {
			name = filepath.Base(file)
		}
		t.Run(name, func(t *testing.T) {
			switch testCase.Kind {
			case "ovpn":
				runOVPNCase(t, testCase)
			case "config":
				runConfigCase(t, testCase)
			case "tags":
				runTagsCase(t, testCase)
			case "snapshot":
				runSnapshotCase(t, testCase)
			case "snapshot_probe":
				runSnapshotProbeCase(t, testCase)
			case "ovpn_error":
				runOVPNErrorCase(t, testCase)
			case "config_error":
				runConfigErrorCase(t, testCase)
			case "nodes_to_endpoints":
				runNodesToEndpointsCase(t, testCase)
			case "remote_policy":
				runRemotePolicyCase(t, testCase)
			default:
				t.Fatalf("unknown golden kind %q", testCase.Kind)
			}
		})
	}
}

// TestPythonParitySafety pins the security-sensitive semantics B implemented
// in vpngate_to_singbox.py. It runs without regenerated golden files, so the
// Lead's gen_golden.py pass only has to add the fixture kinds above.
func TestPythonParitySafety(t *testing.T) {
	profile := func(remote, block string) string {
		return "client\nproto tcp-client\nremote " + remote + "\n" + block
	}
	if _, err := singbox.ParseOVPN(profile("203.0.113.1 443 tcp", "<ca>\n<script>x</script>\n</ca>\n"),
		singbox.ParseOptions{}); err == nil {
		t.Fatal("non-PEM inline block must be rejected")
	}
	commented := profile("203.0.113.1 443 tcp", "# <ca> fake\n<ca>\nQ0E=\n</ca>\n")
	if endpoint, err := singbox.ParseOVPN(commented, singbox.ParseOptions{}); err != nil ||
		endpoint.TLS.Certificate != "Q0E=" {
		t.Fatalf("comment before block affected parsing: %+v %v", endpoint, err)
	}
	for _, remote := range []string{"2002:a9fe:a9fe::1 443 tcp", "2001:0:1234::1 443 tcp", "127.0.0.1 443 tcp"} {
		if _, err := singbox.ParseOVPN(profile(remote, "<ca>\nQ0E=\n</ca>\n"),
			singbox.ParseOptions{}); err == nil {
			t.Fatalf("remote %q must be rejected", remote)
		}
	}
	if _, err := singbox.ParseOVPN(profile("a.example 443 tcp", "<ca>\nQ0E=\n</ca>\n"),
		singbox.ParseOptions{}); err == nil {
		t.Fatal("hostname without resolver must be rejected")
	}

	first := singbox.Endpoint{Type: "openvpn-client", Tag: "dup"}
	second := singbox.Endpoint{Type: "openvpn-client", Tag: "dup"}
	if _, err := singbox.BuildConfig([]singbox.Endpoint{first, second}, singbox.BuildOptions{}); err == nil {
		t.Fatal("duplicate endpoint tags must be rejected")
	}

	nodes := []singbox.Node{
		{Server: "a", ServerPort: 1, Endpoint: singbox.Endpoint{Tag: ""}},
		{Server: "b", ServerPort: 2, Endpoint: singbox.Endpoint{Tag: "vpngate-0"}},
	}
	endpoints := singbox.NodesToEndpoints(nodes, "vpngate")
	if endpoints[0].Tag != "vpngate-1" || endpoints[1].Tag != "vpngate-0" {
		t.Fatalf("explicit tag reservation = %q/%q", endpoints[0].Tag, endpoints[1].Tag)
	}

	csv := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,OpenVPN_ConfigData_Base64\n" +
		row("198.51.100.1", 1000) + row("198.51.100.2", 3000) + row("198.51.100.3", 2000)
	result, err := singbox.SnapshotToNodes(csv, singbox.SnapshotOptions{
		Limit: 2, AllowPrivateRemotes: true,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[0].Server != "198.51.100.2" || result[1].Server != "198.51.100.3" {
		t.Fatalf("limit must apply after full ranking: %#v", result)
	}
	probed, err := singbox.SnapshotToNodes(csv, singbox.SnapshotOptions{
		Limit: 1, Probe: true, ProbePool: 1, ProbeWorkers: 2,
		AllowPrivateRemotes: true,
	}, func(host string, port int) int64 {
		if host == "198.51.100.2" {
			return 0
		}
		return 12
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(probed) != 1 || probed[0].Server != "198.51.100.3" {
		t.Fatalf("probe path = %#v", probed)
	}

	for _, host := range []string{"169.254.169.254", "2002:a9fe:a9fe::1", "2001:0:1234::1", "127.0.0.1"} {
		if _, err := singbox.ValidateRemote(host, 443, false, nil); err == nil {
			t.Fatalf("ValidateRemote(%q) accepted a forbidden address", host)
		}
	}
	if remote, err := singbox.ValidateRemote("203.0.113.5", 443, false, nil); err != nil || remote.Host != "203.0.113.5" {
		t.Fatalf("ValidateRemote(public literal) = %+v %v", remote, err)
	}
}

func row(host string, speed int) string {
	config := "client\nproto tcp-client\nremote " + host + " 443 tcp\n<ca>\nQ0E=\n</ca>\n"
	return host + ",203.0.113.1,0,0," + strconv.Itoa(speed) + ",Country,cc," +
		base64.StdEncoding.EncodeToString([]byte(config)) + "\n"
}

func runOVPNCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	if testCase.Parse == nil {
		t.Fatal("ovpn case has no parse options")
	}
	endpoint, err := singbox.ParseOVPN(testCase.OVPN, singbox.ParseOptions{
		Tag:                 testCase.Parse.Tag,
		Username:            testCase.Parse.Username,
		Password:            testCase.Parse.Password,
		OnDemand:            testCase.Parse.OnDemand,
		AllowPrivateRemotes: testCase.Parse.AllowPrivateRemotes,
	})
	if err != nil {
		t.Fatalf("ParseOVPN: %v", err)
	}
	assertJSONEqual(t, endpoint, testCase.Expected)
}

func runConfigCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	if testCase.Options == nil {
		t.Fatal("config case has no options")
	}
	options := testCase.Options
	build := singbox.BuildOptions{
		MixedListen:     options.MixedListen,
		MixedPort:       options.MixedPort,
		MixedUsers:      make([]singbox.Credential, 0, len(options.MixedUsers)),
		Final:           options.Final,
		Preferred:       options.Preferred,
		Backup:          options.Backup,
		VLESSUUID:       options.VLESSUUID,
		VLESSDirectPort: options.VLESSDirectPort,
		VLESSDirectPath: options.VLESSDirectPath,
		VLESSChainPort:  options.VLESSChainPort,
		VLESSChainPath:  options.VLESSChainPath,
		Resi:            options.Resi,
		ResiPort:        options.ResiPort,
		ResiPath:        options.ResiPath,
		ResiInPort:      options.ResiInPort,
		ResiRotate:      options.ResiRotate,
		ResiRotateBase:  options.ResiRotateBase,
		ClashAPI:        options.ClashAPI,
		PersistentTags:  options.PersistentTags,
	}
	for _, pair := range options.MixedUsers {
		build.MixedUsers = append(build.MixedUsers, singbox.Credential{
			Username: pair[0], Password: pair[1],
		})
	}
	if options.ResiRotateTags != nil {
		build.ResiRotateTags = *options.ResiRotateTags
	}
	if options.ChainCandidates != nil {
		build.ChainCandidates = *options.ChainCandidates
	}
	config, err := singbox.BuildConfig(testCase.Endpoints, build)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	assertJSONEqual(t, config, testCase.Expected)
}

func runTagsCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	nodes := append([]singbox.Node(nil), testCase.New...)
	singbox.AssignStableTags(nodes, testCase.Old, testCase.Prefix)
	assertJSONEqual(t, nodes, testCase.Expected)
}

func runSnapshotCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	nodes, err := singbox.SnapshotToNodes(testCase.CSV, singbox.SnapshotOptions{
		Limit:               testCase.Limit,
		Probe:               false,
		AllowPrivateRemotes: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("SnapshotToNodes: %v", err)
	}
	singbox.AssignStableTags(nodes, nil, testCase.Prefix)
	assertJSONEqual(t, nodes, testCase.Expected)
}

func runSnapshotProbeCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	probe := func(host string, port int) int64 {
		return testCase.ProbeLats[host]
	}
	probePool := testCase.ProbePool
	if probePool == 0 {
		probePool = 30
	}
	probeWorkers := testCase.ProbeWorkers
	if probeWorkers == 0 {
		probeWorkers = 4
	}
	nodes, err := singbox.SnapshotToNodes(testCase.CSV, singbox.SnapshotOptions{
		Limit:               testCase.Limit,
		Probe:               true,
		ProbePool:           probePool,
		ProbeWorkers:        probeWorkers,
		AllowPrivateRemotes: true,
	}, probe, nil)
	if err != nil {
		t.Fatalf("SnapshotToNodes: %v", err)
	}
	singbox.AssignStableTags(nodes, nil, testCase.Prefix)
	assertJSONEqual(t, nodes, testCase.Expected)
}

func runOVPNErrorCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	options := singbox.ParseOptions{AllowPrivateRemotes: testCase.AllowPrivate}
	if testCase.Parse != nil {
		options.Tag = testCase.Parse.Tag
		options.Username = testCase.Parse.Username
		options.Password = testCase.Parse.Password
		options.OnDemand = testCase.Parse.OnDemand
		options.AllowPrivateRemotes = testCase.Parse.AllowPrivateRemotes
	}
	_, err := singbox.ParseOVPN(testCase.OVPN, options)
	if err == nil {
		t.Fatal("expected ParseOVPN to reject the fixture")
	}
	if testCase.ErrorContains != "" && !strings.Contains(err.Error(), testCase.ErrorContains) {
		t.Fatalf("error = %v, want substring %q", err, testCase.ErrorContains)
	}
}

func runConfigErrorCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	if testCase.Options == nil {
		t.Fatal("config_error case has no options")
	}
	_, err := singbox.BuildConfig(testCase.Endpoints, singbox.BuildOptions{
		MixedListen: testCase.Options.MixedListen,
		MixedPort:   testCase.Options.MixedPort,
	})
	if err == nil {
		t.Fatal("expected BuildConfig to reject the fixture")
	}
	if testCase.ErrorContains != "" && !strings.Contains(err.Error(), testCase.ErrorContains) {
		t.Fatalf("error = %v, want substring %q", err, testCase.ErrorContains)
	}
}

func runNodesToEndpointsCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	nodes := append([]singbox.Node(nil), testCase.New...)
	endpoints := singbox.NodesToEndpoints(nodes, testCase.Prefix)
	assertJSONEqual(t, endpoints, testCase.Expected)
}

func runRemotePolicyCase(t *testing.T, testCase goldenCase) {
	t.Helper()
	_, err := singbox.ValidateRemote(testCase.Host, testCase.Port, testCase.AllowPrivate, nil)
	if testCase.ErrorContains != "" {
		if err == nil || !strings.Contains(err.Error(), testCase.ErrorContains) {
			t.Fatalf("ValidateRemote(%q:%d) = %v, want error containing %q",
				testCase.Host, testCase.Port, err, testCase.ErrorContains)
		}
		return
	}
	if err != nil {
		t.Fatalf("ValidateRemote(%q:%d) = %v", testCase.Host, testCase.Port, err)
	}
}

func assertJSONEqual(t *testing.T, got any, want json.RawMessage) {
	t.Helper()
	gotRaw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal Go value: %v", err)
	}
	gotCanonical := canonicalJSON(t, gotRaw)
	wantCanonical := canonicalJSON(t, want)
	if gotCanonical != wantCanonical {
		t.Fatalf("golden mismatch\n--- go ---\n%s\n--- python ---\n%s", gotCanonical, wantCanonical)
	}
}

func canonicalJSON(t *testing.T, raw []byte) string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("re-encode JSON: %v", err)
	}
	return string(encoded)
}
