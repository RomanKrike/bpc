package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGatewayReceiptIsHistoricalEvidenceOnly(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		cluster  string
		revision uint64
		tamper   bool
		valid    bool
	}{
		{"expired trusted", "cluster", 9000, false, true},
		{"foreign cluster", "other", 9000, false, false},
		{"invalid signature", "cluster", 9000, true, false},
		{"overflow", "cluster", ^uint64(0), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			created := time.Now().Unix() - 86400
			raw, _ := json.Marshal(map[string]any{"snapshot_version": 1, "state_schema_version": 1, "cluster_id": test.cluster, "revision": test.revision, "created_at": created, "expires_at": created + 300})
			signed := append([]byte("bpc-gateway-security-snapshot-v1\n"), raw...)
			receipt := revisionReceipt{Signed: signed, Signature: ed25519.Sign(private, signed)}
			if test.tamper {
				receipt.Signature[0] ^= 1
			}
			revision, err := receiptRevision(receipt, "cluster", public)
			if (err == nil) != test.valid || (test.valid && revision != 9000) {
				t.Fatal(revision, err)
			}
		})
	}
}

func TestClusterPeerCannotInitiateRevisionRecovery(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("POST", "https://localhost/v1/reconcile-revision", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	s.reconcileRevision(w, r)
	if w.Code != 403 {
		t.Fatal("cluster peer accepted", w.Code)
	}
}
