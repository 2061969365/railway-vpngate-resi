package singbox

import (
	"strconv"
	"strings"
)

// BuiltinTags are group/inbound names a generated endpoint tag must never
// shadow. Python only guarded against collisions with other endpoint tags;
// the Go port also reserves the fixed sing-box names.
var BuiltinTags = map[string]struct{}{
	"proxy": {}, "auto": {}, "direct": {}, "chain": {},
	"mixed-in": {}, "vless-direct": {}, "vless-chain": {}, "vless-resi": {},
	"resi-in": {}, "dial-probe": {}, "resi": {},
}

// AssignStableTags gives every node a tag that is stable per server:port.
//
// Two passes on purpose (railway_manager.py:327-381): the old tag of every
// *surviving* server:port is reserved before any node gets a tag. A single
// pass let a new fast node inserted at the top of the snapshot take
// "vpngate-0" and only then discover that the old owner was still present,
// silently moving the persisted pin to a different server.
func AssignStableTags(nodes, oldNodes []Node, tagPrefix string) {
	oldTagByKey := make(map[string]string, len(oldNodes))
	for _, old := range oldNodes {
		key := nodeKey(old)
		if old.Endpoint.Tag != "" {
			if _, exists := oldTagByKey[key]; !exists {
				oldTagByKey[key] = old.Endpoint.Tag
			}
		}
	}

	reservedByKey := make(map[string]string, len(nodes))
	reservedTags := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		key := nodeKey(node)
		tag, ok := oldTagByKey[key]
		if !ok || tag == "" {
			continue
		}
		if _, taken := reservedTags[tag]; taken {
			continue
		}
		reservedByKey[key] = tag
		reservedTags[tag] = struct{}{}
	}

	used := make(map[string]struct{}, len(reservedTags))
	for tag := range reservedTags {
		used[tag] = struct{}{}
	}
	counter := 0
	fresh := func() string {
		for {
			candidate := tagPrefix + "-" + strconv.Itoa(counter)
			counter++
			if _, taken := used[candidate]; !taken {
				return candidate
			}
		}
	}

	claimed := make(map[string]struct{}, len(reservedByKey))
	for index := range nodes {
		endpoint := &nodes[index].Endpoint
		key := nodeKey(nodes[index])
		if reserved, ok := reservedByKey[key]; ok {
			if _, already := claimed[reserved]; !already {
				endpoint.Tag = reserved
				claimed[reserved] = struct{}{}
				continue
			}
		}
		if endpoint.Tag != "" {
			if _, taken := used[endpoint.Tag]; !taken {
				used[endpoint.Tag] = struct{}{}
				claimed[endpoint.Tag] = struct{}{}
				continue
			}
		}
		tag := fresh()
		endpoint.Tag = tag
		used[tag] = struct{}{}
		claimed[tag] = struct{}{}
	}
}

// NodesToEndpoints returns the endpoint objects with stable tags. An explicit
// tag survives only when it is unique, not reserved and not already used;
// untagged/duplicate/reserved tags are re-allocated as prefix-N. Reserved
// names are the built-in outbound/inbound tags and the "vless-" namespace.
func NodesToEndpoints(nodes []Node, tagPrefix string) []Endpoint {
	prefix := tagPrefix
	if prefix == "" {
		prefix = "vpngate"
	}
	if tagReserved(prefix) || tagReserved(prefix+"-0") {
		prefix = "vpngate"
	}
	// Reserve every usable explicit tag before allocating anything: an
	// earlier untagged node must not steal the stable tag of a later node.
	explicit := make(map[string]struct{}, len(nodes))
	for index := range nodes {
		tag := nodes[index].Endpoint.Tag
		if tag != "" && !tagReserved(tag) {
			explicit[tag] = struct{}{}
		}
	}
	used := make(map[string]struct{}, len(nodes))
	nextIndex := 0
	endpoints := make([]Endpoint, 0, len(nodes))
	for index := range nodes {
		endpoint := nodes[index].Endpoint
		tag := endpoint.Tag
		if tag == "" || tagReserved(tag) {
			tag = ""
		} else if _, taken := used[tag]; taken {
			tag = ""
		}
		if tag == "" {
			for {
				candidate := prefix + "-" + strconv.Itoa(nextIndex)
				nextIndex++
				if _, taken := used[candidate]; taken {
					continue
				}
				if _, reserved := explicit[candidate]; reserved {
					continue
				}
				if tagReserved(candidate) {
					continue
				}
				tag = candidate
				break
			}
			endpoint.Tag = tag
		}
		used[tag] = struct{}{}
		nodes[index].Endpoint = endpoint
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func tagReserved(tag string) bool {
	lowered := strings.ToLower(tag)
	if _, reserved := BuiltinTags[lowered]; reserved {
		return true
	}
	return strings.HasPrefix(lowered, "vless-")
}

func nodeKey(node Node) string {
	return node.Server + ":" + strconv.Itoa(node.ServerPort)
}
