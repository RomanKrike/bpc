package agentctl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControllerP2PClientProofAndWire(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	deviceID := strings.Repeat("b", 32)
	info := P2PInfo{Capabilities: []string{P2PCapability}, ClusterID: "cluster", DeviceID: deviceID, IssuerPublicKey: base64.StdEncoding.EncodeToString(public), IssuerCertificateSHA256: strings.Repeat("c", 64), AccessSHA256: strings.Repeat("d", 64)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing Device credential")
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/p2p/info" {
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var caps []string
		_ = json.Unmarshal(body["capabilities"], &caps)
		if len(caps) != 1 || caps[0] != P2PCapability {
			t.Error("capability not negotiated")
		}
		switch r.URL.Path {
		case "/v1/p2p/consent":
			var proof string
			_ = json.Unmarshal(body["signature"], &proof)
			raw, _ := base64.StdEncoding.DecodeString(proof)
			message, _ := P2PConsentSigningBytes(token, deviceID, true, info.AccessSHA256)
			if !ed25519.Verify(public, message, raw) {
				t.Error("consent signature not bound to Device/state")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/v1/p2p/issue":
			if len(body) != 2 {
				t.Error("request supplied authority-owned identity fields")
			}
			_ = json.NewEncoder(w).Encode(map[string][]byte{"ticket": []byte("signed-grant")})
		case "/v1/p2p/sync":
			var tickets [][]byte
			_ = json.Unmarshal(body["tickets"], &tickets)
			if len(tickets) != 1 || string(tickets[0]) != "signed-grant" {
				t.Error("ticket encoding mismatch")
			}
			_ = json.NewEncoder(w).Encode(map[string][]byte{"checkpoint": []byte("signed-policy")})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = server.Client()
	got, err := client.FetchP2PInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetP2PConsent(context.Background(), *got, true, base64.StdEncoding.EncodeToString(private)); err != nil {
		t.Fatal(err)
	}
	ticket, err := client.IssueP2PGrant(context.Background(), strings.Repeat("e", 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := client.SyncP2PPolicy(context.Background(), [][]byte{ticket})
	if err != nil || string(policy) != "signed-policy" {
		t.Fatalf("sync failed: %v", err)
	}
}
