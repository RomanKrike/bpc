package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/RomanKrike/bpc/internal/controlplane"
)

type revisionReceipt struct {
	Signed    []byte `json:"signed"`
	Signature []byte `json:"signature"`
}

func (s *server) recoveryState(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Index uint64 `json:"index"`
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid recovery request"})
		return
	}
	view, err := s.node.RecoveryState(request.Index, 10*time.Second)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, view)
}

func (s *server) peerRecovery(member controlplane.ControllerMember, index uint64) (controlplane.RecoveryState, error) {
	var record controllerRecord
	raw, err := os.ReadFile(filepath.Join(s.stateRoot, "cluster/controllers", member.ID+".json"))
	if err != nil {
		return controlplane.RecoveryState{}, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return controlplane.RecoveryState{}, err
	}
	if record.NodeID != member.ID || record.RaftAddress != member.Address || record.State == "revoked" {
		return controlplane.RecoveryState{}, errors.New("invalid recovery member")
	}
	host, _, err := net.SplitHostPort(record.APIAddress)
	if err != nil {
		return controlplane.RecoveryState{}, err
	}
	tlsConfig, err := controlplane.ClientTLSConfig(s.tls, host)
	if err != nil {
		return controlplane.RecoveryState{}, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("recovery redirect refused") }}
	body, _ := json.Marshal(map[string]uint64{"index": index})
	response, err := client.Post("https://"+record.APIAddress+"/v1/recovery-state", "application/json", bytes.NewReader(body))
	if err != nil {
		return controlplane.RecoveryState{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return controlplane.RecoveryState{}, fmt.Errorf("member %s lacks ready recovery support (HTTP %d)", member.ID, response.StatusCode)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || response.TLS.PeerCertificates[0].Subject.CommonName != member.ID {
		return controlplane.RecoveryState{}, errors.New("recovery peer identity mismatch")
	}
	var view controlplane.RecoveryState
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&view); err != nil {
		return view, err
	}
	if view.Version != controlplane.RevisionRecoveryVersion || view.NodeID != member.ID || view.Index != index {
		return view, errors.New("unsupported recovery member or index")
	}
	return view, nil
}

func receiptRevision(receipt revisionReceipt, cluster string, key ed25519.PublicKey) (uint64, error) {
	const domain = "bpc-gateway-security-snapshot-v1\n"
	if !bytes.HasPrefix(receipt.Signed, []byte(domain)) || !ed25519.Verify(key, receipt.Signed, receipt.Signature) {
		return 0, errors.New("untrusted Gateway revision receipt")
	}
	var snapshot struct {
		Version  int    `json:"snapshot_version"`
		Schema   int    `json:"state_schema_version"`
		Cluster  string `json:"cluster_id"`
		Revision uint64 `json:"revision"`
		Created  int64  `json:"created_at"`
		Expires  int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(receipt.Signed[len(domain):], &snapshot); err != nil {
		return 0, err
	}
	// Expired policy is accepted only as historical revision evidence; it is
	// never installed or used to authorize traffic.
	if snapshot.Version != 1 || snapshot.Schema != 1 || snapshot.Cluster != cluster || snapshot.Created <= 0 || snapshot.Expires <= snapshot.Created || snapshot.Expires-snapshot.Created > 3600 || snapshot.Created > time.Now().Unix()+300 || snapshot.Revision == ^uint64(0) {
		return 0, errors.New("invalid Gateway revision receipt")
	}
	return snapshot.Revision, nil
}

func (s *server) reconcileRevision(w http.ResponseWriter, r *http.Request) {
	// Cluster peers cannot initiate an admin migration, even on loopback.
	if r.TLS != nil || !isLoopbackRequest(r) {
		writeJSON(w, 403, map[string]any{"error": "revision recovery requires the local admin API"})
		return
	}
	if !s.node.IsLeader() {
		writeJSON(w, 409, map[string]any{"error": "run revision recovery on the current Leader"})
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var request struct {
		Receipts map[string]revisionReceipt `json:"gateway_receipts"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid revision recovery request"})
		return
	}
	result, err := s.reconcile(request.Receipts)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}

func (s *server) reconcile(receipts map[string]revisionReceipt) (controlplane.MutationResult, error) {
	view, err := s.node.RecoveryState(0, 10*time.Second)
	if err != nil {
		return controlplane.MutationResult{}, err
	}
	status, err := s.node.Status()
	if err != nil {
		return controlplane.MutationResult{}, err
	}
	minimum := max(view.Revision, view.Floor, uint64(1))
	for _, member := range status.Members {
		if member.ID == status.NodeID {
			continue
		}
		peer, err := s.peerRecovery(member, view.Index)
		if err != nil {
			return controlplane.MutationResult{}, err
		}
		if peer.Digest != view.Digest || peer.ConfigurationIndex != view.ConfigurationIndex {
			return controlplane.MutationResult{}, errors.New("members have different canonical state or configuration; catch up before retry")
		}
		minimum = max(minimum, peer.Revision, peer.Floor)
	}
	gateways, err := s.node.RecoveryGateways()
	if err != nil {
		return controlplane.MutationResult{}, err
	}
	if len(receipts) != len(gateways) {
		return controlplane.MutationResult{}, errors.New("supply a signed receipt for every active Gateway")
	}
	if len(gateways) > 0 {
		caRaw, err := os.ReadFile(s.tls.CAFile)
		if err != nil {
			return controlplane.MutationResult{}, err
		}
		block, _ := pem.Decode(caRaw)
		if block == nil {
			return controlplane.MutationResult{}, errors.New("invalid cluster CA")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return controlplane.MutationResult{}, err
		}
		key, ok := ca.PublicKey.(ed25519.PublicKey)
		if !ok {
			return controlplane.MutationResult{}, errors.New("Gateway receipt CA must be Ed25519")
		}
		for _, id := range gateways {
			receipt, ok := receipts[id]
			if !ok {
				return controlplane.MutationResult{}, fmt.Errorf("Gateway receipt missing: %s", id)
			}
			revision, err := receiptRevision(receipt, s.tls.ClusterID, key)
			if err != nil {
				return controlplane.MutationResult{}, err
			}
			minimum = max(minimum, revision)
		}
	}
	result, err := s.node.ReconcileRevision(view, minimum, 10*time.Second)
	if err != nil {
		return result, err
	}
	for _, member := range status.Members {
		if member.ID == status.NodeID {
			continue
		}
		peer, err := s.peerRecovery(member, result.CommitIndex)
		if err != nil {
			return controlplane.MutationResult{}, err
		}
		if peer.Revision < minimum || peer.Digest != view.Digest {
			return controlplane.MutationResult{}, errors.New("reconciliation committed; member confirmation failed; retry safely")
		}
	}
	// Member confirmation can span a leadership/configuration change. Confirm
	// authority again immediately before acknowledging the admin operation.
	final, err := s.node.RecoveryState(0, 10*time.Second)
	if err != nil {
		return controlplane.MutationResult{}, err
	}
	if final.ConfigurationIndex != view.ConfigurationIndex || final.Digest != view.Digest || final.Revision < minimum {
		return controlplane.MutationResult{}, errors.New("state changed during member confirmation; retry safely")
	}
	return result, nil
}
