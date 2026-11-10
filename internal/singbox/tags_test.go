package singbox

import "testing"

func taggedNode(server string, port int, tag string) Node {
	return Node{
		Server: server, ServerPort: port,
		Endpoint: Endpoint{Type: "openvpn-client", Tag: tag, Network: "tcp"},
	}
}

func TestAssignStableTagsTwoPass(t *testing.T) {
	oldNodes := []Node{
		taggedNode("a.example", 443, "vpngate-0"),
		taggedNode("b.example", 443, "vpngate-1"),
	}
	nodes := []Node{
		taggedNode("new.example", 443, ""),
		taggedNode("b.example", 443, "vpngate-1"),
		taggedNode("a.example", 443, "vpngate-0"),
		taggedNode("d.example", 443, ""),
	}
	AssignStableTags(nodes, oldNodes, "vpngate")
	want := []string{"vpngate-2", "vpngate-1", "vpngate-0", "vpngate-3"}
	for index, expected := range want {
		if nodes[index].Endpoint.Tag != expected {
			t.Fatalf("node %d tag = %q, want %q", index, nodes[index].Endpoint.Tag, expected)
		}
	}
}

func TestAssignStableTagsKeepsExplicitUnreserved(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, "custom-a"),
		taggedNode("b.example", 443, ""),
	}
	AssignStableTags(nodes, nil, "vpngate")
	if nodes[0].Endpoint.Tag != "custom-a" {
		t.Fatalf("explicit tag = %q", nodes[0].Endpoint.Tag)
	}
	if nodes[1].Endpoint.Tag != "vpngate-0" {
		t.Fatalf("fresh tag = %q", nodes[1].Endpoint.Tag)
	}
}

func TestAssignStableTagsAvoidsBuiltinNames(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, ""),
		taggedNode("b.example", 443, ""),
	}
	AssignStableTags(nodes, nil, "direct")
	if nodes[0].Endpoint.Tag == "direct" || nodes[1].Endpoint.Tag == "direct" {
		t.Fatalf("builtin tag reused: %q/%q", nodes[0].Endpoint.Tag, nodes[1].Endpoint.Tag)
	}
	if nodes[0].Endpoint.Tag != "direct-0" || nodes[1].Endpoint.Tag != "direct-1" {
		t.Fatalf("tags = %q/%q", nodes[0].Endpoint.Tag, nodes[1].Endpoint.Tag)
	}
}

func TestAssignStableTagsOldDuplicateKeyUsesFirst(t *testing.T) {
	oldNodes := []Node{
		taggedNode("a.example", 443, "first"),
		taggedNode("a.example", 443, "second"),
	}
	nodes := []Node{taggedNode("a.example", 443, "")}
	AssignStableTags(nodes, oldNodes, "vpngate")
	if nodes[0].Endpoint.Tag != "first" {
		t.Fatalf("tag = %q", nodes[0].Endpoint.Tag)
	}
}

func TestNodesToEndpointsDeduplicatesExplicitTags(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, "dup"),
		taggedNode("b.example", 443, "dup"),
		taggedNode("c.example", 443, ""),
	}
	endpoints := NodesToEndpoints(nodes, "vpngate")
	if len(endpoints) != 3 {
		t.Fatalf("endpoints = %d", len(endpoints))
	}
	if endpoints[0].Tag != "dup" {
		t.Fatalf("first tag = %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag == "dup" || endpoints[1].Tag == "" {
		t.Fatalf("second tag = %q", endpoints[1].Tag)
	}
	if endpoints[2].Tag == "" || endpoints[2].Tag == "dup" {
		t.Fatalf("third tag = %q", endpoints[2].Tag)
	}
	if nodes[1].Endpoint.Tag != endpoints[1].Tag {
		t.Fatal("nodes must be updated in place")
	}
}

func TestNodesToEndpointsSkipsExistingPrefixSlots(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, "vpngate-0"),
		taggedNode("b.example", 443, ""),
	}
	endpoints := NodesToEndpoints(nodes, "vpngate")
	if endpoints[0].Tag != "vpngate-0" {
		t.Fatalf("kept tag = %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag != "vpngate-1" {
		t.Fatalf("fresh tag = %q", endpoints[1].Tag)
	}
}

func TestNodesToEndpointsReallocatesReservedTags(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, "direct"),
		taggedNode("b.example", 443, "vless-custom"),
		taggedNode("c.example", 443, "vpngate-0"),
	}
	endpoints := NodesToEndpoints(nodes, "vpngate")
	// Python reserves vpngate-0 for the third node before allocating, so the
	// reserved-tag nodes get the following two slots and the explicit tag is
	// preserved.
	if endpoints[0].Tag != "vpngate-1" {
		t.Fatalf("direct tag = %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag != "vpngate-2" {
		t.Fatalf("vless tag = %q", endpoints[1].Tag)
	}
	if endpoints[2].Tag != "vpngate-0" {
		t.Fatalf("explicit tag = %q", endpoints[2].Tag)
	}
}

func TestNodesToEndpointsReservesLaterExplicitTags(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, ""),
		taggedNode("b.example", 443, "vpngate-0"),
	}
	endpoints := NodesToEndpoints(nodes, "vpngate")
	if endpoints[0].Tag != "vpngate-1" {
		t.Fatalf("untagged node stole a later explicit tag: %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag != "vpngate-0" {
		t.Fatalf("explicit tag = %q", endpoints[1].Tag)
	}
}

func TestNodesToEndpointsReservedNamesAreCaseInsensitive(t *testing.T) {
	nodes := []Node{
		taggedNode("a.example", 443, "Proxy"),
		taggedNode("b.example", 443, "VLESS-custom"),
	}
	endpoints := NodesToEndpoints(nodes, "vpngate")
	for _, endpoint := range endpoints {
		if tagReserved(endpoint.Tag) {
			t.Fatalf("reserved tag survived: %q", endpoint.Tag)
		}
	}
}

func TestNodesToEndpointsFallsBackFromReservedPrefix(t *testing.T) {
	nodes := []Node{taggedNode("a.example", 443, "")}
	endpoints := NodesToEndpoints(nodes, "vless")
	if endpoints[0].Tag != "vpngate-0" {
		t.Fatalf("fallback tag = %q", endpoints[0].Tag)
	}
}
