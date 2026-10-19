package agentctl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

const P2PCapability = "p2p-session-v1"

// P2PInfo is fetched only over the authenticated Controller client. Persist the
// trust pin at enrollment; never overwrite a stored pin from a relay or grant.
type P2PInfo struct {
	Capabilities            []string `json:"capabilities"`
	ClusterID               string   `json:"cluster_id"`
	DeviceID                string   `json:"device_id"`
	IssuerPublicKey         string   `json:"issuer_public_key"`
	IssuerCertificateSHA256 string   `json:"issuer_certificate_sha256"`
	Enabled                 bool     `json:"enabled"`
	AccessSHA256            string   `json:"access_sha256"`
}

func (c *Client) FetchP2PInfo(ctx context.Context) (*P2PInfo, error) {
	var info P2PInfo
	if err := c.doJSON(ctx, http.MethodGet, "/v1/p2p/info", c.Token, nil, &info); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(info.IssuerPublicKey)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != info.IssuerPublicKey || info.ClusterID == "" || !p2pHex(info.DeviceID, 32) || !p2pHex(info.IssuerCertificateSHA256, 64) || len(info.Capabilities) != 1 || info.Capabilities[0] != P2PCapability {
		return nil, errors.New("invalid P2P Controller capabilities/trust")
	}
	return &info, nil
}

func p2pHex(value string, length int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(value) == length && hex.EncodeToString(raw) == value
}

func P2PConsentSigningBytes(token, device string, enabled bool, expected string) ([]byte, error) {
	if !p2pHex(token, 64) || !p2pHex(device, 32) || (expected != "" && !p2pHex(expected, 64)) {
		return nil, errors.New("invalid P2P consent context")
	}
	hash := sha256.Sum256([]byte(token))
	return []byte(fmt.Sprintf("BPC-P2P-CONSENT-v1\n%x\n%s\n%t\n%s", hash, device, enabled, expected)), nil
}

func (c *Client) SetP2PConsent(ctx context.Context, info P2PInfo, enabled bool, devicePrivateKey string) error {
	message, err := P2PConsentSigningBytes(c.Token, info.DeviceID, enabled, info.AccessSHA256)
	if err != nil {
		return err
	}
	proof, err := SignDeviceProof(devicePrivateKey, message)
	if err != nil {
		return err
	}
	body := map[string]any{"enabled": enabled, "expected_sha256": info.AccessSHA256, "signature": proof, "capabilities": []string{P2PCapability}}
	return c.doJSON(ctx, http.MethodPost, "/v1/p2p/consent", c.Token, body, nil)
}

func (c *Client) IssueP2PGrant(ctx context.Context, hostDeviceID string) ([]byte, error) {
	if !p2pHex(hostDeviceID, 32) {
		return nil, errors.New("invalid P2P host identifier")
	}
	var result struct {
		Ticket []byte `json:"ticket"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/p2p/issue", c.Token, map[string]any{"host_device_id": hostDeviceID, "capabilities": []string{P2PCapability}}, &result)
	if err != nil {
		return nil, err
	}
	if len(result.Ticket) == 0 || len(result.Ticket) > 8192 {
		return nil, errors.New("invalid P2P grant response")
	}
	return result.Ticket, nil
}

func (c *Client) SyncP2PPolicy(ctx context.Context, tickets [][]byte) ([]byte, error) {
	if len(tickets) > 16 {
		return nil, errors.New("too many P2P tickets")
	}
	if tickets == nil {
		tickets = [][]byte{}
	}
	for _, ticket := range tickets {
		if len(ticket) == 0 || len(ticket) > 8192 {
			return nil, errors.New("invalid P2P ticket")
		}
	}
	var result struct {
		Checkpoint []byte `json:"checkpoint"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/p2p/sync", c.Token, map[string]any{"tickets": tickets, "capabilities": []string{P2PCapability}}, &result)
	if err != nil {
		return nil, err
	}
	if len(result.Checkpoint) == 0 || len(result.Checkpoint) > 8192 {
		return nil, errors.New("invalid P2P checkpoint response")
	}
	return result.Checkpoint, nil
}
