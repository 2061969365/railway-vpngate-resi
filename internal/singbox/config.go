package singbox

import "fmt"

const (
	// DefaultResiPort is the public third-path port.
	DefaultResiPort = 8084
	// DefaultResiPath is the third-path WebSocket path.
	DefaultResiPath = "/ws-resi"
	// ResiInPort is the loopback mixed inbound used to validate the gateway.
	ResiInPort = 40001
	// ResiRotateBase is the first loopback VLESS inbound of rotate mode.
	ResiRotateBase = 41000
	// DefaultVLESSDirectPort is the /ws-node backend port.
	DefaultVLESSDirectPort = 8080
	// DefaultVLESSChainPort is the /ws-chain backend port.
	DefaultVLESSChainPort = 8082
)

// BuildConfig wraps endpoints in a checkable sing-box configuration with the
// same shape as vpngate_to_singbox.build_singbox_config.
func BuildConfig(endpoints []Endpoint, opts BuildOptions) (map[string]any, error) {
	final := opts.Final
	if final == "" {
		final = "auto"
	}
	directPort := opts.VLESSDirectPort
	if directPort == 0 {
		directPort = DefaultVLESSDirectPort
	}
	directPath := opts.VLESSDirectPath
	if directPath == "" {
		directPath = "/ws-node"
	}
	chainPort := opts.VLESSChainPort
	if chainPort == 0 {
		chainPort = DefaultVLESSChainPort
	}
	chainPath := opts.VLESSChainPath
	if chainPath == "" {
		chainPath = "/ws-chain"
	}
	resiPort := opts.ResiPort
	if resiPort == 0 {
		resiPort = DefaultResiPort
	}
	resiPath := opts.ResiPath
	if resiPath == "" {
		resiPath = DefaultResiPath
	}
	resiInPort := opts.ResiInPort
	if resiInPort == 0 {
		resiInPort = ResiInPort
	}

	if len(opts.PersistentTags) > 0 {
		persistent := make(map[string]struct{}, len(opts.PersistentTags))
		for _, tag := range opts.PersistentTags {
			persistent[tag] = struct{}{}
		}
		copied := make([]Endpoint, len(endpoints))
		for index := range endpoints {
			copied[index] = endpoints[index]
			if _, hold := persistent[copied[index].Tag]; hold {
				copied[index].OnDemand = Bool(false)
			} else if copied[index].OnDemand == nil {
				copied[index].OnDemand = Bool(true)
			}
		}
		endpoints = copied
	}
	if endpoints == nil {
		endpoints = []Endpoint{}
	}

	tags := make([]string, 0, len(endpoints))
	seenTags := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if _, duplicate := seenTags[endpoint.Tag]; duplicate {
			return nil, fmt.Errorf("duplicate endpoint tags in sing-box config")
		}
		seenTags[endpoint.Tag] = struct{}{}
		tags = append(tags, endpoint.Tag)
	}
	preferred := opts.Preferred
	if preferred != "" && !containsString(tags, preferred) {
		preferred = ""
	}
	backup := opts.Backup
	if backup != "" && (!containsString(tags, backup) || backup == preferred) {
		backup = ""
	}
	routeFinal := final
	if preferred != "" {
		routeFinal = "chain"
	}

	proxyMembers := append(append([]string{}, tags...), "direct")
	autoMembers := append([]string{}, tags...)
	outbounds := []any{
		map[string]any{"type": "selector", "tag": "proxy", "outbounds": proxyMembers},
		map[string]any{"type": "urltest", "tag": "auto", "outbounds": autoMembers,
			"interval": "15s", "tolerance": 150},
		map[string]any{"type": "direct", "tag": "direct"},
	}
	if preferred != "" {
		ordered := []string{preferred}
		for _, tag := range opts.ChainCandidates {
			if containsString(tags, tag) && !containsString(ordered, tag) {
				ordered = append(ordered, tag)
			}
		}
		if backup != "" && containsString(tags, backup) && !containsString(ordered, backup) {
			ordered = append(ordered, backup)
		}
		if opts.ChainCandidates == nil && !containsString(ordered, "auto") {
			ordered = append(ordered, "auto")
		}
		outbounds = append(outbounds, map[string]any{
			"type": "selector", "tag": "chain", "outbounds": ordered,
			"default": preferred, "interrupt_exist_connections": false,
		})
	}

	config := map[string]any{
		"log":       map[string]any{"level": "info"},
		"endpoints": endpoints,
		"outbounds": outbounds,
		"route":     map[string]any{"final": routeFinal, "auto_detect_interface": true},
	}

	var inbounds []any
	if opts.MixedListen != "" && opts.MixedPort != 0 {
		inbound := map[string]any{
			"type": "mixed", "tag": "mixed-in",
			"listen": opts.MixedListen, "listen_port": opts.MixedPort,
		}
		if len(opts.MixedUsers) > 0 {
			inbound["users"] = opts.MixedUsers
		}
		inbounds = append(inbounds, inbound)
	}
	if opts.VLESSUUID != nil {
		if opts.MixedListen == "" || opts.MixedPort == 0 {
			return nil, fmt.Errorf("vless inbounds need the mixed inbound ($PORT mux target)")
		}
		uuid := *opts.VLESSUUID
		inbounds = append(inbounds,
			map[string]any{
				"type": "vless", "tag": "vless-direct",
				"listen": "0.0.0.0", "listen_port": directPort,
				"users":     []map[string]any{{"uuid": uuid}},
				"transport": map[string]any{"type": "ws", "path": directPath},
			},
			map[string]any{
				"type": "vless", "tag": "vless-chain",
				"listen": "0.0.0.0", "listen_port": chainPort,
				"users":     []map[string]any{{"uuid": uuid}},
				"transport": map[string]any{"type": "ws", "path": chainPath},
			})
	}

	var rules []any
	if opts.VLESSUUID != nil {
		chainTarget := "auto"
		if preferred != "" {
			chainTarget = "chain"
		}
		rules = append(rules,
			map[string]any{"inbound": "vless-direct", "outbound": "direct"},
			map[string]any{"inbound": "vless-chain", "outbound": chainTarget},
		)
	}

	if opts.ResiRotate && opts.Resi != nil {
		return nil, fmt.Errorf("resi and resi_rotate are mutually exclusive")
	}
	if opts.Resi != nil {
		if opts.VLESSUUID == nil {
			return nil, fmt.Errorf("resi outbound needs the vless inbound (set VLESS_UUID)")
		}
		outbounds = append(outbounds, map[string]any{
			"type": "socks", "tag": "resi",
			"server": opts.Resi.Server, "server_port": opts.Resi.ServerPort,
			"version": "5", "username": opts.Resi.Username,
			"password": opts.Resi.Password, "network": "tcp",
		})
		config["outbounds"] = outbounds
		uuid := *opts.VLESSUUID
		inbounds = append(inbounds,
			map[string]any{
				"type": "vless", "tag": "vless-resi",
				"listen": "0.0.0.0", "listen_port": resiPort,
				"users":     []map[string]any{{"uuid": uuid}},
				"transport": map[string]any{"type": "ws", "path": resiPath},
			},
			map[string]any{
				"type": "mixed", "tag": "resi-in",
				"listen": "127.0.0.1", "listen_port": resiInPort,
			})
		rules = append(rules,
			map[string]any{"inbound": "vless-resi", "outbound": "resi"},
			map[string]any{"inbound": "resi-in", "outbound": "resi"},
		)
	}
	if opts.ResiRotate {
		if opts.VLESSUUID == nil {
			return nil, fmt.Errorf("resi_rotate needs VLESS_UUID (its inbounds are VLESS+WS)")
		}
		rotateBase := opts.ResiRotateBase
		if rotateBase == 0 {
			rotateBase = ResiRotateBase
		}
		rotateEndpoints := endpoints
		if opts.ResiRotateTags != nil {
			byTag := make(map[string]Endpoint, len(endpoints))
			for _, endpoint := range endpoints {
				byTag[endpoint.Tag] = endpoint
			}
			rotateEndpoints = make([]Endpoint, 0, len(opts.ResiRotateTags))
			for _, tag := range opts.ResiRotateTags {
				if endpoint, ok := byTag[tag]; ok {
					rotateEndpoints = append(rotateEndpoints, endpoint)
				}
			}
		}
		uuid := *opts.VLESSUUID
		for index, endpoint := range rotateEndpoints {
			inbounds = append(inbounds, map[string]any{
				"type": "vless", "tag": fmt.Sprintf("resi-rot-%d", index),
				"listen": "127.0.0.1", "listen_port": rotateBase + index,
				"users":     []map[string]any{{"uuid": uuid}},
				"transport": map[string]any{"type": "ws", "path": resiPath},
			})
			rules = append(rules, map[string]any{
				"inbound": fmt.Sprintf("resi-rot-%d", index), "outbound": endpoint.Tag,
			})
		}
	}
	if len(inbounds) > 0 {
		config["inbounds"] = inbounds
	}
	if len(rules) > 0 {
		route := config["route"].(map[string]any)
		route["rules"] = rules
	}
	if opts.ClashAPI != nil {
		config["experimental"] = map[string]any{"clash_api": opts.ClashAPI}
	}
	return config, nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
