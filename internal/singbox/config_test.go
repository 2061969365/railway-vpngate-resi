package singbox

import (
	"encoding/json"
	"testing"
)

func buildEndpoint(t *testing.T, host, tag string) Endpoint {
	t.Helper()
	endpoint, err := ParseOVPN(profileFor(host, 443), ParseOptions{
		Tag: tag, OnDemand: true, AllowPrivateRemotes: true,
	})
	if err != nil {
		t.Fatalf("ParseOVPN(%s): %v", host, err)
	}
	return endpoint
}

func asMap(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("not a map: %T", value)
	}
	return out
}

func TestBuildConfigBasic(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1",
		MixedPort:   40000,
		MixedUsers:  []Credential{{Username: "u", Password: "p"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if level := asMap(t, config["log"])["level"]; level != "info" {
		t.Fatalf("log level = %v", level)
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) != 3 {
		t.Fatalf("outbounds = %#v", config["outbounds"])
	}
	proxy := asMap(t, outbounds[0])
	if proxy["tag"] != "proxy" {
		t.Fatalf("proxy = %#v", proxy)
	}
	members, _ := proxy["outbounds"].([]string)
	if len(members) != 2 || members[0] != "vpngate-0" || members[1] != "direct" {
		t.Fatalf("proxy members = %#v", members)
	}
	route := asMap(t, config["route"])
	if route["final"] != "auto" || route["auto_detect_interface"] != true {
		t.Fatalf("route = %#v", route)
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("inbounds = %#v", config["inbounds"])
	}
	mixed := asMap(t, inbounds[0])
	users, _ := mixed["users"].([]Credential)
	if len(users) != 1 || users[0].Username != "u" {
		t.Fatalf("users = %#v", mixed["users"])
	}
	endpoints, _ := config["endpoints"].([]Endpoint)
	if len(endpoints) != 1 || endpoints[0].Tag != "vpngate-0" {
		t.Fatalf("endpoints = %#v", config["endpoints"])
	}
	if _, err := json.Marshal(config); err != nil {
		t.Fatalf("config is not JSON serializable: %v", err)
	}
}

func TestBuildConfigPersistentTags(t *testing.T) {
	first := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	second := buildEndpoint(t, "198.51.100.2", "vpngate-1")
	second.OnDemand = nil
	config, err := BuildConfig([]Endpoint{first, second}, BuildOptions{
		MixedListen:    "127.0.0.1",
		MixedPort:      40000,
		PersistentTags: []string{"vpngate-0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoints, _ := config["endpoints"].([]Endpoint)
	if endpoints[0].OnDemand == nil || *endpoints[0].OnDemand {
		t.Fatalf("persistent on_demand = %v", endpoints[0].OnDemand)
	}
	if endpoints[1].OnDemand == nil || !*endpoints[1].OnDemand {
		t.Fatalf("absent on_demand must become true, got %v", endpoints[1].OnDemand)
	}
}

func TestBuildConfigChainSelector(t *testing.T) {
	endpoints := []Endpoint{
		buildEndpoint(t, "198.51.100.1", "vpngate-0"),
		buildEndpoint(t, "198.51.100.2", "vpngate-1"),
		buildEndpoint(t, "198.51.100.3", "vpngate-2"),
	}
	config, err := BuildConfig(endpoints, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		Preferred: "vpngate-1", Backup: "vpngate-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 4 {
		t.Fatalf("outbounds = %d", len(outbounds))
	}
	chain := asMap(t, outbounds[3])
	members, _ := chain["outbounds"].([]string)
	if len(members) != 3 || members[0] != "vpngate-1" || members[1] != "vpngate-2" || members[2] != "auto" {
		t.Fatalf("chain members = %#v", members)
	}
	if chain["default"] != "vpngate-1" || chain["interrupt_exist_connections"] != false {
		t.Fatalf("chain = %#v", chain)
	}
	if asMap(t, config["route"])["final"] != "chain" {
		t.Fatalf("route = %#v", config["route"])
	}
}

func TestBuildConfigChainCandidatesSuppressAuto(t *testing.T) {
	endpoints := []Endpoint{
		buildEndpoint(t, "198.51.100.1", "vpngate-0"),
		buildEndpoint(t, "198.51.100.2", "vpngate-1"),
		buildEndpoint(t, "198.51.100.3", "vpngate-2"),
	}
	candidates := []string{"vpngate-0", "vpngate-2", "missing"}
	config, err := BuildConfig(endpoints, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		Preferred: "vpngate-1", Backup: "vpngate-2",
		ChainCandidates: candidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := asMap(t, config["outbounds"].([]any)[3])
	members, _ := chain["outbounds"].([]string)
	want := []string{"vpngate-1", "vpngate-0", "vpngate-2"}
	if len(members) != len(want) {
		t.Fatalf("chain members = %#v", members)
	}
	for index := range want {
		if members[index] != want[index] {
			t.Fatalf("chain members = %#v", members)
		}
	}
}

func TestBuildConfigUnknownPreferredFallsBack(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		Preferred: "missing", Backup: "vpngate-0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if asMap(t, config["route"])["final"] != "auto" {
		t.Fatalf("route = %#v", config["route"])
	}
	if len(config["outbounds"].([]any)) != 3 {
		t.Fatalf("chain selector must not exist: %#v", config["outbounds"])
	}
}

func TestBuildConfigVLESS(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	uuid := "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		VLESSUUID:       &uuid,
		VLESSDirectPort: 8080, VLESSChainPort: 8082,
	})
	if err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 3 {
		t.Fatalf("inbounds = %d", len(inbounds))
	}
	direct := asMap(t, inbounds[1])
	if direct["tag"] != "vless-direct" || direct["listen_port"] != 8080 {
		t.Fatalf("direct = %#v", direct)
	}
	rules, _ := asMap(t, config["route"])["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %#v", rules)
	}
	if asMap(t, rules[1])["outbound"] != "auto" {
		t.Fatalf("chain rule = %#v", rules[1])
	}
}

func TestBuildConfigVLESSRequiresMixed(t *testing.T) {
	uuid := "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
	if _, err := BuildConfig(nil, BuildOptions{VLESSUUID: &uuid}); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildConfigResi(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	uuid := "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		VLESSUUID:       &uuid,
		VLESSDirectPort: 8080, VLESSChainPort: 8082,
		Resi:     &ResiOutbound{Server: "192.0.2.10", ServerPort: 1080, Username: "ru", Password: "rp"},
		ResiPort: 8084, ResiPath: "/ws-resi",
	})
	if err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	last := asMap(t, outbounds[len(outbounds)-1])
	if last["tag"] != "resi" || last["server"] != "192.0.2.10" || last["network"] != "tcp" {
		t.Fatalf("resi outbound = %#v", last)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 5 {
		t.Fatalf("inbounds = %d", len(inbounds))
	}
	if asMap(t, inbounds[4])["tag"] != "resi-in" {
		t.Fatalf("resi-in = %#v", inbounds[4])
	}
	rules := asMap(t, config["route"])["rules"].([]any)
	if len(rules) != 4 {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestBuildConfigResiRotate(t *testing.T) {
	endpoints := []Endpoint{
		buildEndpoint(t, "198.51.100.1", "vpngate-0"),
		buildEndpoint(t, "198.51.100.2", "vpngate-1"),
		buildEndpoint(t, "198.51.100.3", "vpngate-2"),
	}
	uuid := "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
	config, err := BuildConfig(endpoints, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		VLESSUUID:       &uuid,
		VLESSDirectPort: 8080, VLESSChainPort: 8082,
		ResiRotate:     true,
		ResiRotateTags: []string{"vpngate-2", "vpngate-0"},
		ResiPath:       "/ws-resi",
	})
	if err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 5 {
		t.Fatalf("inbounds = %d", len(inbounds))
	}
	first := asMap(t, inbounds[3])
	if first["tag"] != "resi-rot-0" || first["listen_port"] != 41000 {
		t.Fatalf("first rotate = %#v", first)
	}
	second := asMap(t, inbounds[4])
	if second["listen_port"] != 41001 {
		t.Fatalf("second rotate = %#v", second)
	}
	rules := asMap(t, config["route"])["rules"].([]any)
	if asMap(t, rules[2])["outbound"] != "vpngate-2" || asMap(t, rules[3])["outbound"] != "vpngate-0" {
		t.Fatalf("rotate rules = %#v", rules)
	}
}

func TestBuildConfigResiValidation(t *testing.T) {
	uuid := "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
	resi := &ResiOutbound{Server: "192.0.2.10", ServerPort: 1080, Username: "u", Password: "p"}
	if _, err := BuildConfig(nil, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		Resi: resi,
	}); err == nil {
		t.Fatal("resi without vless must fail")
	}
	if _, err := BuildConfig(nil, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		ResiRotate: true,
	}); err == nil {
		t.Fatal("rotate without vless must fail")
	}
	if _, err := BuildConfig(nil, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		VLESSUUID: &uuid, Resi: resi, ResiRotate: true,
	}); err == nil {
		t.Fatal("resi and rotate are mutually exclusive")
	}
}

func TestBuildConfigRejectsDuplicateTags(t *testing.T) {
	first := buildEndpoint(t, "198.51.100.1", "dup")
	second := buildEndpoint(t, "198.51.100.2", "dup")
	if _, err := BuildConfig([]Endpoint{first, second}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
	}); err == nil {
		t.Fatal("duplicate endpoint tags must be rejected")
	}
}

func TestBuildConfigResiRotateBaseOption(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	uuid := "uuid"
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		VLESSUUID: &uuid, ResiRotate: true, ResiRotateBase: 43000,
	})
	if err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	found := false
	for _, inbound := range inbounds {
		item := asMap(t, inbound)
		if item["tag"] == "resi-rot-0" {
			found = true
			if item["listen_port"] != 43000 {
				t.Fatalf("rotate port = %v", item["listen_port"])
			}
		}
	}
	if !found {
		t.Fatal("resi-rot-0 inbound missing")
	}
}

func TestBuildConfigClashAPI(t *testing.T) {
	endpoint := buildEndpoint(t, "198.51.100.1", "vpngate-0")
	config, err := BuildConfig([]Endpoint{endpoint}, BuildOptions{
		MixedListen: "127.0.0.1", MixedPort: 40000,
		ClashAPI: &ClashAPI{ExternalController: "127.0.0.1:9090", Secret: "s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	experimental := asMap(t, config["experimental"])
	clash, ok := experimental["clash_api"].(*ClashAPI)
	if !ok || clash.ExternalController != "127.0.0.1:9090" || clash.Secret != "s" {
		t.Fatalf("clash api = %#v", experimental["clash_api"])
	}
}
