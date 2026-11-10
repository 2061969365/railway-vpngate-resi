// Package singbox holds the pure functions ported from
// vpngate_to_singbox.py: OpenVPN profile parsing, VPNGate snapshot parsing,
// stable tag assignment and sing-box configuration generation. It performs no
// network or process I/O so Python golden fixtures can be replayed directly.
package singbox

// ServerAddr is one entry of an endpoint's servers[] failover list.
type ServerAddr struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Network    string `json:"network,omitempty"`
}

// ControlWrap mirrors sing-box's openvpn control_wrap (tls-auth/tls-crypt).
type ControlWrap struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	Direction string `json:"direction,omitempty"`
}

// TLS is the openvpn-client TLS object. field names match the Python dict.
type TLS struct {
	Certificate        string       `json:"certificate"`
	CertificateProfile string       `json:"certificate_profile"`
	ClientCertificate  string       `json:"client_certificate,omitempty"`
	ClientKey          string       `json:"client_key,omitempty"`
	ControlWrap        *ControlWrap `json:"control_wrap,omitempty"`
}

// Endpoint is one sing-box openvpn-client endpoint. Optional fields use
// pointers/omitempty so an absent field stays absent, exactly like the Python
// dict that omits keys it did not read from the profile.
type Endpoint struct {
	Type                string       `json:"type"`
	Tag                 string       `json:"tag"`
	Server              string       `json:"server,omitempty"`
	ServerPort          int          `json:"server_port,omitempty"`
	Servers             []ServerAddr `json:"servers,omitempty"`
	Network             string       `json:"network"`
	Username            string       `json:"username"`
	Password            string       `json:"password"`
	TLS                 TLS          `json:"tls"`
	DataCiphers         []string     `json:"data_ciphers"`
	DataCiphersFallback string       `json:"data_ciphers_fallback"`
	Auth                string       `json:"auth"`
	AuthRetry           string       `json:"auth_retry"`
	OnDemand            *bool        `json:"on_demand,omitempty"`
	PingInterval        string       `json:"ping_interval,omitempty"`
	PingRestart         string       `json:"ping_restart,omitempty"`
	PingRestartDisabled *bool        `json:"ping_restart_disabled,omitempty"`
	RenegotiateDisabled *bool        `json:"renegotiate_disabled,omitempty"`
	RenegotiateInterval string       `json:"renegotiate_interval,omitempty"`
	RemoteRandom        *bool        `json:"remote_random,omitempty"`
	System              bool         `json:"system"`
	RedirectGateway     bool         `json:"redirect_gateway"`
}

// Node is one parsed snapshot node with its measured latency.
type Node struct {
	Server        string   `json:"server"`
	ServerPort    int      `json:"server_port"`
	Country       string   `json:"country"`
	CountryShort  string   `json:"country_short"`
	Speed         int64    `json:"speed"`
	LatencyMS     *int64   `json:"latency_ms"`
	RealLatencyMS *int64   `json:"real_latency_ms"`
	Endpoint      Endpoint `json:"endpoint"`
}

// Credential is one mixed inbound user.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ResiOutbound is the residential SOCKS5 gateway outbound.
type ResiOutbound struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

// ClashAPI is the loopback Clash API experimental section.
type ClashAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
}

// BuildOptions mirrors build_singbox_config's keyword arguments. Empty
// Preferred/Backup mean "not pinned". ChainCandidates nil means "not
// supplied" (the chain selector then gets the automatic "auto" tail);
// a non-nil empty slice means "supplied but empty".
type BuildOptions struct {
	MixedListen     string
	MixedPort       int
	MixedUsers      []Credential
	Final           string
	Preferred       string
	Backup          string
	VLESSUUID       *string
	VLESSDirectPort int
	VLESSDirectPath string
	VLESSChainPort  int
	VLESSChainPath  string
	Resi            *ResiOutbound
	ResiPort        int
	ResiPath        string
	ResiInPort      int
	ResiRotate      bool
	ResiRotateBase  int
	ResiRotateTags  []string
	ChainCandidates []string
	ClashAPI        *ClashAPI
	PersistentTags  []string
}

// Bool returns a pointer to v (helper for optional booleans).
func Bool(v bool) *bool { return &v }

// Int64 returns a pointer to v (helper for optional latency fields).
func Int64(v int64) *int64 { return &v }
