package agentctl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	BootstrapVersion       = 3
	LegacyBootstrapVersion = 2
	StateVersion           = 2
	LegacyStateVersion     = 1
)

type Bootstrap struct {
	Version         int    `json:"version"`
	Device          string `json:"device"`
	ControlURL      string `json:"control_url"`
	EnrollToken     string `json:"enroll_token"`
	UpdatePublicKey string `json:"update_public_key"`
	LegacyTunnel    string `json:"legacy_tunnel,omitempty"`
}

type RuntimeConfig struct {
	ConfigVersion int               `json:"config_version"`
	WGShimServer  string            `json:"wgshim_server"`
	WGShimServers []string          `json:"wgshim_servers,omitempty"`
	WGShimListen  string            `json:"wgshim_listen"`
	WGShimTarget  string            `json:"wgshim_target"`
	WGShimPSK     string            `json:"wgshim_psk"`
	PaddingMin    int               `json:"padding_min"`
	PaddingMax    int               `json:"padding_max"`
	LegacyTunnel  string            `json:"legacy_tunnel,omitempty"`
	UpdateChannel string            `json:"update_channel,omitempty"`
	WireGuard     *WireGuardProfile `json:"wireguard,omitempty"`
}

type State struct {
	Version          int              `json:"version"`
	DeviceID         string           `json:"device_id"`
	DeviceName       string           `json:"device_name"`
	AccessToken      string           `json:"access_token,omitempty"`
	AccessExpiresAt  int64            `json:"access_expires_at,omitempty"`
	RefreshToken     string           `json:"refresh_token,omitempty"`
	RefreshExpiresAt int64            `json:"refresh_expires_at,omitempty"`
	DeviceToken      string           `json:"device_token,omitempty"` // Stage 2 compatibility only.
	PublicKey        string           `json:"public_key"`
	PrivateKey       string           `json:"private_key"`
	ControlURL       string           `json:"control_url"`
	UpdatePubKey     string           `json:"update_public_key"`
	Config           RuntimeConfig    `json:"config"`
	WireGuard        WireGuardProfile `json:"wireguard"`
}

type EnrollmentRequest struct {
	Token              string `json:"token"`
	Device             string `json:"device"`
	PublicKey          string `json:"public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	Version            string `json:"version"`
}

type EnrollmentResponse struct {
	DeviceID    string           `json:"device_id"`
	DeviceToken string           `json:"device_token"`
	Config      RuntimeConfig    `json:"config"`
	WireGuard   WireGuardProfile `json:"wireguard"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken     string `json:"access_token"`
	AccessExpiresAt int64  `json:"access_expires_at"`
	User            struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
}

type DeviceRegistrationRequest struct {
	Name               string `json:"name"`
	PublicKey          string `json:"public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	Version            string `json:"version"`
	Proof              string `json:"proof"`
}

type DeviceRegistrationResponse struct {
	DeviceID         string           `json:"device_id"`
	AccessToken      string           `json:"access_token"`
	AccessExpiresAt  int64            `json:"access_expires_at"`
	RefreshToken     string           `json:"refresh_token"`
	RefreshExpiresAt int64            `json:"refresh_expires_at"`
	Config           RuntimeConfig    `json:"config"`
	WireGuard        WireGuardProfile `json:"wireguard"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	Proof        string `json:"proof"`
}

type RefreshResponse struct {
	DeviceID         string `json:"device_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresAt int64  `json:"refresh_expires_at"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type DeviceSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	Enabled   bool   `json:"enabled"`
	RevokedAt *int64 `json:"revoked_at"`
}

type DeviceListResponse struct {
	Devices []DeviceSummary `json:"devices"`
}

type HeartbeatRequest struct {
	Version   string `json:"version"`
	Transport string `json:"transport,omitempty"`
	Status    string `json:"status,omitempty"`
}

type UpdateManifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient(baseURL, token string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse control URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("control URL must be HTTPS")
	}
	return &Client{
		BaseURL: baseURL,
		Token:   strings.TrimSpace(token),
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func (c *Client) Enroll(ctx context.Context, req EnrollmentRequest) (*EnrollmentResponse, error) {
	var response EnrollmentResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/enroll", "", req, &response); err != nil {
		return nil, err
	}
	if response.DeviceID == "" || response.DeviceToken == "" {
		return nil, errors.New("control plane returned incomplete enrollment response")
	}
	if strings.TrimSpace(response.WireGuard.Address) == "" ||
		strings.TrimSpace(response.WireGuard.PeerPublicKey) == "" {
		return nil, errors.New("control plane returned incomplete WireGuard profile")
	}
	return &response, nil
}

func (c *Client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	var response LoginResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/auth/login", "", LoginRequest{
		Username: username,
		Password: password,
	}, &response); err != nil {
		return nil, err
	}
	if response.AccessToken == "" || response.AccessExpiresAt == 0 || response.User.ID == "" {
		return nil, errors.New("control plane returned incomplete login response")
	}
	return &response, nil
}

func (c *Client) RegisterDevice(
	ctx context.Context,
	accessToken string,
	req DeviceRegistrationRequest,
) (*DeviceRegistrationResponse, error) {
	var response DeviceRegistrationResponse
	if err := c.doJSON(
		ctx,
		http.MethodPost,
		"/v1/devices/register",
		accessToken,
		req,
		&response,
	); err != nil {
		return nil, err
	}
	if response.DeviceID == "" || response.AccessToken == "" || response.RefreshToken == "" {
		return nil, errors.New("control plane returned incomplete device registration response")
	}
	if strings.TrimSpace(response.WireGuard.Address) == "" ||
		strings.TrimSpace(response.WireGuard.PeerPublicKey) == "" {
		return nil, errors.New("control plane returned incomplete WireGuard profile")
	}
	return &response, nil
}

func (c *Client) Refresh(
	ctx context.Context,
	refreshToken string,
	proof string,
) (*RefreshResponse, error) {
	var response RefreshResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/auth/refresh", "", RefreshRequest{
		RefreshToken: refreshToken,
		Proof:        proof,
	}, &response); err != nil {
		return nil, err
	}
	if response.AccessToken == "" || response.RefreshToken == "" ||
		response.AccessExpiresAt == 0 || response.RefreshExpiresAt == 0 {
		return nil, errors.New("control plane returned incomplete refresh response")
	}
	return &response, nil
}

func (c *Client) Logout(ctx context.Context, accessToken, refreshToken string) error {
	return c.doJSON(
		ctx,
		http.MethodPost,
		"/v1/auth/logout",
		accessToken,
		LogoutRequest{RefreshToken: refreshToken},
		nil,
	)
}

func (c *Client) ListDevices(ctx context.Context, accessToken string) ([]DeviceSummary, error) {
	var response DeviceListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/devices", accessToken, nil, &response); err != nil {
		return nil, err
	}
	return response.Devices, nil
}

func (c *Client) RevokeDevice(ctx context.Context, accessToken, deviceID string) error {
	body := struct {
		DeviceID string `json:"device_id"`
	}{DeviceID: deviceID}
	return c.doJSON(ctx, http.MethodPost, "/v1/devices/revoke", accessToken, body, nil)
}

func (c *Client) FetchConfig(ctx context.Context) (*RuntimeConfig, error) {
	var cfg RuntimeConfig
	if err := c.doJSON(ctx, http.MethodGet, "/v1/config", c.Token, nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/heartbeat", c.Token, req, nil)
}

func (c *Client) FetchUpdateManifest(ctx context.Context) (*UpdateManifest, error) {
	var manifest UpdateManifest
	if err := c.doJSON(ctx, http.MethodGet, "/v1/update/manifest", c.Token, nil, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version == "" {
		return nil, errors.New("update manifest does not contain a version")
	}
	return &manifest, nil
}

func (c *Client) Download(ctx context.Context, rawURL string, dst string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse download URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("update download URL must be HTTPS")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("download update: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".download"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, io.LimitReader(resp.Body, 128<<20))
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	token string,
	body any,
	out any,
) error {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode %s %s response: %w", method, path, err)
	}
	return nil
}

func GenerateIdentity() (publicB64, privateB64 string, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey),
		base64.StdEncoding.EncodeToString(privateKey), nil
}

func SignDeviceProof(privateB64 string, message []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateB64))
	if err != nil {
		return "", fmt.Errorf("decode device private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return "", errors.New("device private key has invalid length")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(raw), message)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func RegistrationSigningBytes(
	accessToken string,
	publicKey string,
	wireGuardPublicKey string,
) []byte {
	return []byte(
		"bpc-register-v1\n" +
			strings.TrimSpace(accessToken) + "\n" +
			strings.TrimSpace(publicKey) + "\n" +
			strings.TrimSpace(wireGuardPublicKey) + "\n",
	)
}

func RefreshSigningBytes(refreshToken string) []byte {
	return []byte("bpc-refresh-v1\n" + strings.TrimSpace(refreshToken) + "\n")
}

func (s *State) ControlCredential() string {
	if strings.TrimSpace(s.AccessToken) != "" {
		return strings.TrimSpace(s.AccessToken)
	}
	return strings.TrimSpace(s.DeviceToken)
}

func (s *State) NeedsRefresh(now time.Time) bool {
	if strings.TrimSpace(s.RefreshToken) == "" {
		return false
	}
	if strings.TrimSpace(s.AccessToken) == "" {
		return true
	}
	return s.AccessExpiresAt <= now.Add(60*time.Second).Unix()
}

func ValidateBootstrap(cfg Bootstrap) error {
	if cfg.Version != BootstrapVersion && cfg.Version != LegacyBootstrapVersion {
		return fmt.Errorf("unsupported bootstrap version %d", cfg.Version)
	}
	if strings.TrimSpace(cfg.Device) == "" {
		return errors.New("bootstrap device is empty")
	}
	if cfg.Version == LegacyBootstrapVersion && strings.TrimSpace(cfg.EnrollToken) == "" {
		return errors.New("legacy bootstrap enrollment token is empty")
	}
	if _, err := NewClient(cfg.ControlURL, ""); err != nil {
		return err
	}
	if _, err := ParseUpdatePublicKey(cfg.UpdatePublicKey); err != nil {
		return fmt.Errorf("bootstrap update public key: %w", err)
	}
	return nil
}

func ValidateRuntimeConfig(cfg RuntimeConfig) error {
	required := map[string]string{
		"wgshim_server": cfg.WGShimServer,
		"wgshim_listen": cfg.WGShimListen,
		"wgshim_target": cfg.WGShimTarget,
		"wgshim_psk":    cfg.WGShimPSK,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("runtime config field %s is empty", name)
		}
	}
	servers := cfg.WGShimServers
	if len(servers) == 0 {
		servers = []string{cfg.WGShimServer}
	}
	if len(servers) > 16 {
		return fmt.Errorf("runtime WGShim server pool is too large: %d", len(servers))
	}
	seenServers := map[string]struct{}{}
	for _, endpoint := range servers {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return errors.New("runtime WGShim server list contains an empty endpoint")
		}
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return fmt.Errorf("invalid WGShim server endpoint %q: %w", endpoint, err)
		}
		if _, exists := seenServers[endpoint]; exists {
			return fmt.Errorf("duplicate WGShim server endpoint %q", endpoint)
		}
		seenServers[endpoint] = struct{}{}
	}
	if len(cfg.WGShimServers) > 0 {
		if _, ok := seenServers[strings.TrimSpace(cfg.WGShimServer)]; !ok {
			return errors.New("runtime WGShim server pool does not contain the primary endpoint")
		}
	}
	key, err := base64.StdEncoding.DecodeString(cfg.WGShimPSK)
	if err != nil || len(key) != 32 {
		return errors.New("runtime WGShim key is invalid")
	}
	if cfg.PaddingMin < 0 || cfg.PaddingMax < cfg.PaddingMin || cfg.PaddingMax > 255 {
		return errors.New("runtime padding range is invalid")
	}
	if cfg.WireGuard != nil {
		if err := ValidateWireGuardServerProfile(*cfg.WireGuard); err != nil {
			return fmt.Errorf("runtime WireGuard profile: %w", err)
		}
	}
	return nil
}

func SaveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}

func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.Version != StateVersion && state.Version != LegacyStateVersion {
		return nil, fmt.Errorf("unsupported agent state version %d", state.Version)
	}
	return &state, nil
}

func ParseUpdatePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("public key PEM is invalid")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("update public key is not Ed25519")
	}
	return publicKey, nil
}

func VerifyUpdateManifest(manifest UpdateManifest, encodedPublicKey string) error {
	if manifest.Version == "" || manifest.URL == "" || manifest.SHA256 == "" || manifest.Signature == "" {
		return errors.New("update manifest is incomplete")
	}
	if _, err := hex.DecodeString(manifest.SHA256); err != nil || len(manifest.SHA256) != sha256.Size*2 {
		return errors.New("update manifest SHA256 is invalid")
	}
	publicKey, err := ParseUpdatePublicKey(encodedPublicKey)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return errors.New("update manifest signature is invalid base64")
	}
	if !ed25519.Verify(publicKey, manifestSigningBytes(manifest), signature) {
		return errors.New("update manifest signature verification failed")
	}
	return nil
}

func VerifyFileSHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expected)) {
		return fmt.Errorf("update SHA256 mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func UpdateSigningBytes(manifest UpdateManifest) []byte {
	return manifestSigningBytes(manifest)
}

func manifestSigningBytes(manifest UpdateManifest) []byte {
	return []byte(manifest.Version + "\n" + strings.ToLower(manifest.SHA256) + "\n" + manifest.URL + "\n")
}

func IsNewerVersion(candidate, current string) bool {
	a, okA := parseStableSemver(candidate)
	b, okB := parseStableSemver(current)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

func parseStableSemver(value string) ([3]int, bool) {
	var result [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(parts) != 3 {
		return result, false
	}
	for i, part := range parts {
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || fmt.Sprintf("%d", n) != part {
			return result, false
		}
		result[i] = n
	}
	return result, true
}
