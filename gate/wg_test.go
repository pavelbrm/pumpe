package gate

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"syscall"
	"testing"

	"github.com/kenshaw/ini"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/model"
)

func TestWireGuard_close(t *testing.T) {
	tests := []testCase[*WireGuard, error]{
		{
			name: "error",
			given: &WireGuard{
				dev: &wgDev{
					fnDown: func() error {
						return model.Error("something_went_wrong")
					},

					fnClose: func() {
						panic("unexpected_close")
					},
				},
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "error",
			given: &WireGuard{
				dev: &wgDev{},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.close()
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestWGConfig_toProto(t *testing.T) {
	type tcExpected struct {
		proto string
		err   error
	}

	tests := []testCase[*WGConfig, tcExpected]{
		{
			name: "error_pvt_key",
			given: &WGConfig{
				Iface: struct {
					PrivateKey string
					Address    []string
				}{
					PrivateKey: "aW52YWxpZA==",
					Address:    []string{"192.168.4.28/32"},
				},
				Peer: struct {
					PublicKey  string
					Endpoint   string
					AllowedIPs []string
				}{
					PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
					Endpoint:   "127.0.0.1:58120",
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
			exp: tcExpected{
				err: ErrInvalidWGKey,
			},
		},

		{
			name: "error_pub_key",
			given: &WGConfig{
				Iface: struct {
					PrivateKey string
					Address    []string
				}{
					PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
					Address:    []string{"192.168.4.28/32"},
				},
				Peer: struct {
					PublicKey  string
					Endpoint   string
					AllowedIPs []string
				}{
					PublicKey:  "aW52YWxpZA==",
					Endpoint:   "127.0.0.1:58120",
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
			exp: tcExpected{
				err: ErrInvalidWGKey,
			},
		},

		{
			name: "valid",
			given: &WGConfig{
				Iface: struct {
					PrivateKey string
					Address    []string
				}{
					PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
					Address:    []string{"192.168.4.28/32"},
				},
				Peer: struct {
					PublicKey  string
					Endpoint   string
					AllowedIPs []string
				}{
					PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
					Endpoint:   "127.0.0.1:58120",
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
			exp: tcExpected{
				proto: "private_key=087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379\npublic_key=c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28\nendpoint=127.0.0.1:58120\nallowed_ip=0.0.0.0/0\n",
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.toProto()
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.proto, actual)
		})
	}
}

func TestParseWGConfigs(t *testing.T) {
	type tcGiven struct {
		mode WGParseMode
		dir  string
	}

	type tcExpected struct {
		wgs []*WGConfig
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_not_exist",
			given: tcGiven{
				dir: "this/path/does/not/exist",
			},
			exp: tcExpected{
				err: &fs.PathError{Op: "open", Path: "this/path/does/not/exist", Err: syscall.ENOENT},
			},
		},

		{
			name: "error_stop",
			given: tcGiven{
				mode: WGParseModeStop,
				dir:  "./testdata/wg",
			},
			exp: tcExpected{
				err: ErrInvalidWGConfig,
			},
		},

		{
			name: "error_report",
			given: tcGiven{
				mode: WGParseModeReport,
				dir:  "./testdata/wg",
			},
			exp: tcExpected{
				wgs: []*WGConfig{
					{
						Iface: struct {
							PrivateKey string
							Address    []string
						}{
							PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
							Address:    []string{"192.168.4.28/32"},
						},
						Peer: struct {
							PublicKey  string
							Endpoint   string
							AllowedIPs []string
						}{
							PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
							Endpoint:   "127.0.0.1:58120",
							AllowedIPs: []string{"0.0.0.0/0"},
						},
					},
				},
				err: errors.Join(
					fmt.Errorf("failed to parse file: %s: %w", ".invalid_data", ErrInvalidWGConfig),
					fmt.Errorf("failed to parse file: %s: %w", "wg_invalid_no_iface.ini", ErrInvalidWGConfig),
					fmt.Errorf("failed to parse file: %s: %w", "wg_invalid_no_peer.ini", ErrInvalidWGConfig),
				),
			},
		},

		{
			name: "valid_ignore",
			given: tcGiven{
				mode: WGParseModeIgnore,
				dir:  "./testdata/wg",
			},
			exp: tcExpected{
				wgs: []*WGConfig{
					{
						Iface: struct {
							PrivateKey string
							Address    []string
						}{
							PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
							Address:    []string{"192.168.4.28/32"},
						},
						Peer: struct {
							PublicKey  string
							Endpoint   string
							AllowedIPs []string
						}{
							PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
							Endpoint:   "127.0.0.1:58120",
							AllowedIPs: []string{"0.0.0.0/0"},
						},
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseWGConfigs(tc.given.mode, tc.given.dir)
			must.Equal(t, tc.exp.err, err)

			if tc.given.mode == WGParseModeStop && tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.wgs, actual)
		})
	}
}

func TestParseWGConfig(t *testing.T) {
	type tcExpected struct {
		cfg *WGConfig
		err error
	}

	tests := []testCase[string, tcExpected]{
		{
			name:  "error_not_exist",
			given: "this/path/does/not/exist/wg.ini",
			exp: tcExpected{
				err: &fs.PathError{Op: "open", Path: "this/path/does/not/exist/wg.ini", Err: syscall.ENOENT},
			},
		},

		{
			name:  "error_invalid",
			given: "./testdata/wg/wg_invalid_no_iface.ini",
			exp: tcExpected{
				err: ErrInvalidWGConfig,
			},
		},

		{
			name:  "valid",
			given: "./testdata/wg/wg_valid.ini",
			exp: tcExpected{
				cfg: &WGConfig{
					Iface: struct {
						PrivateKey string
						Address    []string
					}{
						PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
						Address:    []string{"192.168.4.28/32"},
					},
					Peer: struct {
						PublicKey  string
						Endpoint   string
						AllowedIPs []string
					}{
						PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
						Endpoint:   "127.0.0.1:58120",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseWGConfig(tc.given)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.cfg, actual)
		})
	}
}

func TestParseWFConfigINI(t *testing.T) {
	type tcExpected struct {
		cfg *WGConfig
		err error
	}

	tests := []testCase[[]byte, tcExpected]{
		{
			name:  "error_load",
			given: []byte{34, 147, 92, 117, 48, 48, 48, 49, 34},
			exp: tcExpected{
				// The returned error has unexported fields.
				err: func() error {
					_, err := ini.LoadBytes([]byte{34, 147, 92, 117, 48, 48, 48, 49, 34})

					return err
				}(),
			},
		},

		{
			name:  "error_invalid_no_iface",
			given: []byte("[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:58120"),
			exp: tcExpected{
				err: ErrInvalidWGConfig,
			},
		},

		{
			name:  "error_invalid_no_peer",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8"),
			exp: tcExpected{
				err: ErrInvalidWGConfig,
			},
		},

		{
			name:  "error_no_private_key",
			given: []byte("[Interface]\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:58120\n"),
			exp: tcExpected{
				err: ErrInvalidWGIfacePvtKey,
			},
		},

		{
			name:  "error_no_address",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:58120\n"),
			exp: tcExpected{
				err: ErrInvalidWGIfaceAddr,
			},
		},

		{
			name:  "error_no_public_key",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:58120\n"),
			exp: tcExpected{
				err: ErrInvalidWGPeerPubKey,
			},
		},

		{
			name:  "error_no_endpoint",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nAllowedIPs = 0.0.0.0/0\n"),
			exp: tcExpected{
				err: ErrInvalidWGPeerEndpoint,
			},
		},

		{
			name:  "error_no_allowed_ips",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nEndpoint = 127.0.0.1:58120\n"),
			exp: tcExpected{
				err: ErrInvalidWGPeerAllowedIP,
			},
		},

		{
			name:  "valid",
			given: []byte("[Interface]\nPrivateKey = CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=\nAddress = 192.168.4.28/32\nDNS = 8.8.8.8\n\n[Peer]\nPublicKey = xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:58120\n"),
			exp: tcExpected{
				cfg: &WGConfig{
					Iface: struct {
						PrivateKey string
						Address    []string
					}{
						PrivateKey: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
						Address:    []string{"192.168.4.28/32"},
					},
					Peer: struct {
						PublicKey  string
						Endpoint   string
						AllowedIPs []string
					}{
						PublicKey:  "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
						Endpoint:   "127.0.0.1:58120",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseWGConfigINI(tc.given)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.cfg, actual)
		})
	}
}

func TestSplitTrimString(t *testing.T) {
	type tcGiven struct {
		raw string
		sep string
	}

	tests := []testCase[tcGiven, []string]{
		{
			name: "empty",
		},

		{
			name:  "empty_raw",
			given: tcGiven{sep: ","},
		},

		{
			name:  "empty_sep",
			given: tcGiven{raw: "something"},
			exp:   []string{"s", "o", "m", "e", "t", "h", "i", "n", "g"},
		},

		{
			name: "skip_empty_parts",
			given: tcGiven{
				raw: "one, two, , ,     , three",
				sep: ",",
			},
			exp: []string{"one", "two", "three"},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := splitTrimString(tc.given.raw, tc.given.sep)
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestParseIPAddrsFromCIDR(t *testing.T) {
	type tcExpected struct {
		addrs []netip.Addr
		err   error
	}

	tests := []testCase[[]string, tcExpected]{
		{
			name:  "error_not_cidr",
			given: []string{"192.168.0.1"},
			exp:   tcExpected{err: errors.New(`netip.ParsePrefix("192.168.0.1"): no '/'`)},
		},

		{
			name:  "valid_single",
			given: []string{"192.168.0.1/24"},
			exp: tcExpected{
				addrs: []netip.Addr{netip.MustParseAddr("192.168.0.1")},
			},
		},

		{
			name:  "valid_multiple",
			given: []string{"192.168.0.1/24", "10.0.0.1/16"},
			exp: tcExpected{
				addrs: []netip.Addr{netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("10.0.0.1")},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseIPAddrsFromCIDR(tc.given)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.addrs, actual)
		})
	}
}

func TestParseIPAddrs(t *testing.T) {
	type tcExpected struct {
		addrs []netip.Addr
		err   error
	}

	tests := []testCase[[]string, tcExpected]{
		{
			name:  "error_cidr",
			given: []string{"192.168.0.1/24"},
			exp: tcExpected{
				err: func() error {
					_, err := netip.ParseAddr("192.168.0.1/24")
					return err
				}(),
			},
		},

		{
			name:  "valid_single",
			given: []string{"192.168.0.1"},
			exp: tcExpected{
				addrs: []netip.Addr{netip.MustParseAddr("192.168.0.1")},
			},
		},

		{
			name:  "valid_multiple",
			given: []string{"192.168.0.1", "10.0.0.1"},
			exp: tcExpected{
				addrs: []netip.Addr{netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("10.0.0.1")},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseIPAddrs(tc.given)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.addrs, actual)
		})
	}
}

func TestRecodeBase64ToHex(t *testing.T) {
	type tcExpected struct {
		b64 string
		hex string
	}

	tests := []testCase[string, tcExpected]{
		{
			name:  "key_01",
			given: "087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379",
			exp: tcExpected{
				b64: "CH7G4Uu+0hDnIVzcc0aN+iPwgKG/uGZbL9gJvZnSg3k=",
				hex: "087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379",
			},
		},

		{
			name:  "key_02",
			given: "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28",
			exp: tcExpected{
				b64: "xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg=",
				hex: "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28",
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actualB64, err1 := recodeHexToBase64(tc.given)
			must.Equal(t, nil, err1)

			should.Equal(t, tc.exp.b64, actualB64)

			actualHex, err2 := recodeBase64ToHex(actualB64)
			must.Equal(t, nil, err2)

			should.Equal(t, tc.exp.hex, actualHex)
		})
	}
}
