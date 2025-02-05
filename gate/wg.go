package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kenshaw/ini"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	WGParseModeReport WGParseMode = iota
	WGParseModeStop
	WGParseModeIgnore
)

type WGParseMode int

type WireGuard struct {
	*baseGate
	dev  wgDownCloser
	netd netDialer
	doer httpDoer
}

func NewWireGuard(lg *slog.Logger, cfg *WGConfig, dnsAddr netip.Addr, tout time.Duration) (*WireGuard, error) {
	return newWireGuardWithFactory(lg, cfg, dnsAddr, tout, &wgCreator{})
}

func newWireGuardWithFactory(lg *slog.Logger, cfg *WGConfig, dnsAddr netip.Addr, tout time.Duration, wf wgFactory) (*WireGuard, error) {
	return wf.new(lg, cfg, dnsAddr, tout)
}

func newWireGuard(id uuid.UUID, dev wgDownCloser, netd netDialer, doer httpDoer) *WireGuard {
	result := &WireGuard{
		baseGate: newBaseGateID(KindWireGuard, id),
		dev:      dev,
		netd:     netd,
		doer:     doer,
	}

	return result
}

func (g *WireGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.netd.DialContext(ctx, network, addr)
}

func (g *WireGuard) Do(r *http.Request) (*http.Response, error) {
	return g.doer.Do(r)
}

func (g *WireGuard) warmup(ctx context.Context) (time.Duration, error) {
	return warmupDoer(ctx, g.doer)
}

func (g *WireGuard) refresh() error {
	return ErrNotImplemented
}

func (g *WireGuard) close() error {
	if err := g.dev.down(); err != nil {
		return err
	}

	g.dev.close()

	return nil
}

func NewWireGuards(lg *slog.Logger, cfgs []*WGConfig, dnsAddr netip.Addr, tout time.Duration) ([]*WireGuard, error) {
	wf := &wgCreator{}

	var result []*WireGuard

	for i := range cfgs {
		wg, err := newWireGuardWithFactory(lg, cfgs[i], dnsAddr, tout, wf)
		if err != nil {
			return nil, err
		}

		result = append(result, wg)
	}

	return result, nil
}

type WGConfig struct {
	Iface struct {
		PrivateKey string
		Address    []string
	}

	Peer struct {
		PublicKey  string
		Endpoint   string
		AllowedIPs []string
	}
}

func (c *WGConfig) toProto() (string, error) {
	pvtKey, err := recodeBase64ToHex(c.Iface.PrivateKey)
	if err != nil {
		return "", err
	}

	pubKey, err := recodeBase64ToHex(c.Peer.PublicKey)
	if err != nil {
		return "", err
	}

	cfg := &bytes.Buffer{}
	cfg.WriteString("private_key=" + pvtKey + "\n")
	cfg.WriteString("public_key=" + pubKey + "\n")
	cfg.WriteString("endpoint=" + c.Peer.Endpoint + "\n")

	for i := range c.Peer.AllowedIPs {
		cfg.WriteString("allowed_ip=" + c.Peer.AllowedIPs[i] + "\n")
	}

	return cfg.String(), nil
}

// ParseWGConfigsWithMode parses files in dir.
//
// It handles errors based on the mode:
// - WGParseModeReport -> collect encountered errors and report along with successful results;
//   - when returned error is not nil, the caller can unwrap and explore it;
//
// - WGParseModeStop -> stop as soon as encountered an error;
//
// - WGParseModeIgnore -> ignore all encountered _parsing_ errors;
//   - non-parsing errors may still be reported.
func ParseWGConfigs(mode WGParseMode, dir string) ([]*WGConfig, error) {
	return parseWGConfigs(mode, dir)
}

func ParseWGConfig(fpath string) (*WGConfig, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return parseWGConfigINI(data)
}

func parseWGConfigs(mode WGParseMode, dir string) ([]*WGConfig, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	return parseWGConfigsDir(mode, dir, files)
}

func parseWGConfigsDir(mode WGParseMode, dpath string, files []fs.DirEntry) ([]*WGConfig, error) {
	result := make([]*WGConfig, 0)

	var errs []error

	for i := range files {
		if !files[i].Type().IsRegular() {
			continue
		}

		name := files[i].Name()

		cfg, err := ParseWGConfig(filepath.Join(dpath, name))
		if err != nil {
			if mode == WGParseModeIgnore {
				continue
			}

			if mode == WGParseModeReport {
				errs = append(errs, fmt.Errorf("failed to parse file: %s: %w", name, err))
				continue
			}

			return nil, err
		}

		result = append(result, cfg)
	}

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}

	return result, nil
}

func parseWGConfigINI(data []byte) (*WGConfig, error) {
	f, err := ini.LoadBytes(data)
	if err != nil {
		return nil, err
	}

	result := &WGConfig{}

	siface := f.GetSection("Interface")
	speer := f.GetSection("Peer")

	if siface == nil || speer == nil {
		return nil, ErrInvalidWGConfig
	}

	result.Iface.PrivateKey = siface.Get("PrivateKey")
	if result.Iface.PrivateKey == "" {
		return nil, ErrInvalidWGIfacePvtKey
	}

	result.Iface.Address = splitTrimString(siface.Get("Address"), ",")
	if len(result.Iface.Address) == 0 {
		return nil, ErrInvalidWGIfaceAddr
	}

	result.Peer.PublicKey = speer.Get("PublicKey")
	if result.Peer.PublicKey == "" {
		return nil, ErrInvalidWGPeerPubKey
	}

	result.Peer.Endpoint = speer.Get("Endpoint")
	if result.Peer.Endpoint == "" {
		return nil, ErrInvalidWGPeerEndpoint
	}

	result.Peer.AllowedIPs = splitTrimString(speer.Get("AllowedIPs"), ",")
	if len(result.Peer.AllowedIPs) == 0 {
		return nil, ErrInvalidWGPeerAllowedIP
	}

	return result, nil
}

func splitTrimString(raw, sep string) []string {
	parts := strings.Split(raw, sep)

	var result []string
	for i := range parts {
		if v := strings.TrimSpace(parts[i]); v != "" {
			result = append(result, v)
		}
	}

	return result
}

func parseIPAddrsFromCIDR(raw []string) ([]netip.Addr, error) {
	var result []netip.Addr

	for i := range raw {
		part, err := netip.ParsePrefix(raw[i])
		if err != nil {
			return nil, err
		}

		result = append(result, part.Addr())
	}

	return result, nil
}

func parseIPAddrs(raw []string) ([]netip.Addr, error) {
	var result []netip.Addr

	for i := range raw {
		part, err := netip.ParseAddr(raw[i])
		if err != nil {
			return nil, err
		}

		result = append(result, part)
	}

	return result, nil
}

func newDevLoggerFromSlog(lg *slog.Logger) *device.Logger {
	result := &device.Logger{
		Verbosef: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			lg.LogAttrs(context.TODO(), slog.LevelDebug, msg)
		},
		Errorf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			lg.LogAttrs(context.TODO(), slog.LevelError, msg)
		},
	}

	return result
}

func recodeBase64ToHex(val string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return "", err
	}

	if len(raw) != 32 {
		return "", ErrInvalidWGKey
	}

	return hex.EncodeToString(raw), nil
}

func recodeHexToBase64(val string) (string, error) {
	raw, err := hex.DecodeString(val)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

type wgCreator struct{}

func (c *wgCreator) new(lg *slog.Logger, cfg *WGConfig, dnsAddr netip.Addr, tout time.Duration) (*WireGuard, error) {
	addrs, err := parseIPAddrsFromCIDR(cfg.Iface.Address)
	if err != nil {
		return nil, err
	}

	if len(cfg.Iface.Address) == 0 {
		return nil, ErrInvalidWGIfaceAddr
	}

	pcfg, err := cfg.toProto()
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{dnsAddr}, 1420)
	if err != nil {
		return nil, err
	}

	id := uuid.New()

	wlg := lg.With(
		slog.String("gate.kind", KindWireGuard.String()),
		slog.String("gate.id", id.String()),
	)

	dev := device.NewDevice(tun, conn.NewDefaultBind(), newDevLoggerFromSlog(wlg))

	if err := dev.IpcSet(pcfg); err != nil {
		return nil, err
	}

	if err := dev.Up(); err != nil {
		return nil, err
	}

	wdev := &wgDev{fnDown: dev.Down, fnClose: dev.Close}
	doer := &http.Client{
		Timeout: tout,
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	return newWireGuard(id, wdev, tnet, doer), nil
}

type wgDownCloser interface {
	down() error
	close()
}

type wgDev struct {
	fnDown  func() error
	fnClose func()
}

func (d *wgDev) down() error {
	if d.fnDown == nil {
		return nil
	}

	return d.fnDown()
}

func (d *wgDev) close() {
	if d.fnClose == nil {
		return
	}

	d.fnClose()
}
