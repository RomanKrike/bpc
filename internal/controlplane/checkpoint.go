package controlplane

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

const maxCheckpointBytes = 192 * 1024 * 1024
const maxCheckpointStateBytes = 128 * 1024 * 1024

// ReplayCheckpoint couples a Raft-created snapshot with its own metadata.
// A logical export or separately sampled status index is not a replay base.
type ReplayCheckpoint struct {
	Version      int               `json:"version"`
	ClusterID    string            `json:"cluster_id"`
	SourceNodeID string            `json:"source_node_id"`
	Meta         raft.SnapshotMeta `json:"meta"`
	State        []byte            `json:"state"`
	SHA256       string            `json:"sha256"`
}

type CheckpointImportResult struct {
	SnapshotIndex uint64
	RevisionFloor uint64
	BackupFile    string
}

func checkpointChecksum(checkpoint ReplayCheckpoint) string {
	checkpoint.SHA256 = ""
	raw, _ := json.Marshal(checkpoint)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (n *Node) ExportReplayCheckpoint(timeout time.Duration) (ReplayCheckpoint, error) {
	if _, _, err := n.StrongRead(timeout); err != nil {
		return ReplayCheckpoint{}, err
	}
	if err := n.Snapshot(); err != nil && !errors.Is(err, raft.ErrNothingNewToSnapshot) {
		return ReplayCheckpoint{}, err
	}
	available, err := n.snapshots.List()
	if err != nil {
		return ReplayCheckpoint{}, err
	}
	if len(available) == 0 {
		return ReplayCheckpoint{}, errors.New("no Raft snapshot available")
	}
	meta, reader, err := n.snapshots.Open(available[0].ID)
	if err != nil {
		return ReplayCheckpoint{}, err
	}
	defer reader.Close()
	state, err := io.ReadAll(io.LimitReader(reader, maxCheckpointStateBytes+1))
	if err != nil {
		return ReplayCheckpoint{}, err
	}
	if len(state) > maxCheckpointStateBytes {
		return ReplayCheckpoint{}, errors.New("Raft snapshot is too large")
	}
	clusterID, err := SnapshotClusterID(state)
	if err != nil {
		return ReplayCheckpoint{}, err
	}
	// A leadership change cannot make the snapshot uncommitted, but require the
	// selected source to remain leader so operators get an explicit retry.
	if !n.IsLeader() {
		return ReplayCheckpoint{}, ErrNotLeader
	}
	checkpoint := ReplayCheckpoint{Version: 1, ClusterID: clusterID, SourceNodeID: n.config.NodeID, Meta: *meta, State: state}
	checkpoint.SHA256 = checkpointChecksum(checkpoint)
	return checkpoint, nil
}

func validateReplayCheckpoint(checkpoint ReplayCheckpoint, config NodeConfig, recipient, source *x509.Certificate) error {
	if checkpoint.Version != 1 || checkpoint.SourceNodeID == "" || checkpoint.SourceNodeID == config.NodeID || checkpoint.ClusterID != config.TLS.ClusterID {
		return errors.New("checkpoint identity/version mismatch")
	}
	if len(checkpoint.State) > maxCheckpointStateBytes || checkpoint.SHA256 != checkpointChecksum(checkpoint) {
		return errors.New("checkpoint checksum/size mismatch")
	}
	meta := checkpoint.Meta
	if meta.Version != raft.SnapshotVersionMax || meta.Index == 0 || meta.Term == 0 || meta.ConfigurationIndex == 0 || meta.ConfigurationIndex > meta.Index || meta.Size != int64(len(checkpoint.State)) {
		return errors.New("invalid checkpoint Raft metadata")
	}
	clusterID, err := SnapshotClusterID(checkpoint.State)
	if err != nil {
		return err
	}
	if clusterID != checkpoint.ClusterID {
		return errors.New("checkpoint canonical cluster mismatch")
	}
	var envelope snapshotEnvelope
	if err := json.Unmarshal(checkpoint.State, &envelope); err != nil {
		return err
	}
	for path := range envelope.Entries {
		normalized, err := NormalizeReplicatedPath(path)
		if err != nil || normalized != path {
			return fmt.Errorf("invalid checkpoint canonical path %q", path)
		}
	}
	seen := map[raft.ServerID]bool{}
	recipientFound, sourceFound := false, false
	for _, member := range meta.Configuration.Servers {
		if member.ID == "" || member.Address == "" || seen[member.ID] || (member.Suffrage != raft.Voter && member.Suffrage != raft.Nonvoter) {
			return errors.New("invalid checkpoint membership configuration")
		}
		seen[member.ID] = true
		if string(member.ID) == config.NodeID {
			if string(member.Address) != config.RaftAddress {
				return errors.New("checkpoint recipient Raft address mismatch")
			}
			recipientFound = true
		}
		if string(member.ID) == checkpoint.SourceNodeID && member.Suffrage == raft.Voter {
			sourceFound = true
		}
	}
	if !recipientFound || !sourceFound {
		return errors.New("checkpoint does not include recipient and source Controller")
	}
	for nodeID, cert := range map[string]*x509.Certificate{config.NodeID: recipient, checkpoint.SourceNodeID: source} {
		if cert == nil || cert.Subject.CommonName != nodeID {
			return errors.New("checkpoint certificate identity mismatch")
		}
		var record membershipRecord
		if err := json.Unmarshal(envelope.Entries["cluster/controllers/"+nodeID+".json"], &record); err != nil {
			return errors.New("checkpoint membership record unavailable")
		}
		digest := sha256.Sum256(cert.Raw)
		if record.NodeID != nodeID || strings.ToLower(record.CertificateSHA256) != hex.EncodeToString(digest[:]) || (record.State != "voter" && record.State != "nonvoter" && record.State != "pending") {
			return errors.New("checkpoint does not authorize authenticated certificates")
		}
		if nodeID == checkpoint.SourceNodeID && record.State != "voter" {
			return errors.New("checkpoint source is not a canonical voter")
		}
	}
	return nil
}

// ImportReplayCheckpoint runs only with the recipient DB exclusively locked.
// The canonical state and identity stay untouched until normal Raft startup
// restores this base and catches up through a quorum-confirmed barrier.
func ImportReplayCheckpoint(config NodeConfig, source string) (CheckpointImportResult, error) {
	endpoint, err := url.Parse(source)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return CheckpointImportResult{}, errors.New("checkpoint source must be an HTTPS Controller origin")
	}
	if config.NodeID == "" || config.RaftAddress == "" || config.TLS.ClusterID == "" || config.TLS.MembershipDir == "" {
		return CheckpointImportResult{}, errors.New("checkpoint recipient identity/trust configuration is incomplete")
	}
	dbPath := filepath.Join(config.DataDir, "raft-state.db")
	info, err := os.Stat(dbPath)
	if err != nil || !info.Mode().IsRegular() {
		return CheckpointImportResult{}, errors.New("checkpoint import requires an existing stopped Controller DB")
	}
	store, err := OpenStore(dbPath)
	if err != nil {
		return CheckpointImportResult{}, fmt.Errorf("stop recipient bpc-controld before importing checkpoint: %w", err)
	}
	defer store.Close()
	tlsConfig, err := ClientTLSConfig(config.TLS, endpoint.Hostname())
	if err != nil {
		return CheckpointImportResult{}, err
	}
	recipient, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		return CheckpointImportResult{}, err
	}
	endpoint.Path = "/v1/replay-checkpoint"
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("checkpoint redirects are forbidden") }}
	response, err := client.Post(endpoint.String(), "application/json", nil)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CheckpointImportResult{}, fmt.Errorf("checkpoint source returned HTTP %d; select an upgraded ready Leader", response.StatusCode)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return CheckpointImportResult{}, errors.New("checkpoint source TLS identity missing")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxCheckpointBytes+1))
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if len(raw) > maxCheckpointBytes {
		return CheckpointImportResult{}, errors.New("checkpoint response is too large")
	}
	var checkpoint ReplayCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return CheckpointImportResult{}, err
	}
	if checkpoint.SourceNodeID != response.TLS.PeerCertificates[0].Subject.CommonName {
		return CheckpointImportResult{}, errors.New("checkpoint source does not match authenticated TLS peer")
	}
	return installReplayCheckpoint(store, config, checkpoint, recipient, response.TLS.PeerCertificates[0])
}

func installReplayCheckpoint(store *Store, config NodeConfig, checkpoint ReplayCheckpoint, recipient, source *x509.Certificate) (CheckpointImportResult, error) {
	if err := validateReplayCheckpoint(checkpoint, config, recipient, source); err != nil {
		return CheckpointImportResult{}, err
	}
	localCluster, exists, err := store.canonicalGet("cluster/cluster.json")
	if err != nil {
		return CheckpointImportResult{}, err
	}
	var identity struct {
		ClusterID string `json:"cluster_id"`
	}
	if !exists || json.Unmarshal(localCluster, &identity) != nil || identity.ClusterID != checkpoint.ClusterID {
		return CheckpointImportResult{}, errors.New("checkpoint does not match recipient canonical DB cluster")
	}
	if err := os.Chmod(config.DataDir, 0o700); err != nil {
		return CheckpointImportResult{}, err
	}
	// Preserve every existing snapshot during this offline operation. Normal
	// runtime retention applies only when future Raft snapshots are created.
	snapshots, err := raft.NewFileSnapshotStore(config.DataDir, int(^uint(0)>>1), io.Discard)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	available, err := snapshots.List()
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if len(available) != 0 && available[0].Index >= checkpoint.Meta.Index {
		return CheckpointImportResult{}, errors.New("recipient already has an equal or newer Raft checkpoint; refusing replacement")
	}
	backupDir := filepath.Join(config.DataDir, "replay-backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return CheckpointImportResult{}, err
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return CheckpointImportResult{}, err
	}
	backup, err := os.CreateTemp(backupDir, "before-checkpoint-*.db")
	if err != nil {
		return CheckpointImportResult{}, err
	}
	backupPath := backup.Name()
	err = store.db.View(func(tx *bolt.Tx) error { _, err := tx.WriteTo(backup); return err })
	if err == nil {
		err = backup.Sync()
	}
	closeErr := backup.Close()
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if closeErr != nil {
		return CheckpointImportResult{}, closeErr
	}
	backupParent, err := os.Open(backupDir)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	err = backupParent.Sync()
	closeErr = backupParent.Close()
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if closeErr != nil {
		return CheckpointImportResult{}, closeErr
	}
	dataParent, err := os.Open(config.DataDir)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	err = dataParent.Sync()
	closeErr = dataParent.Close()
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if closeErr != nil {
		return CheckpointImportResult{}, closeErr
	}
	// FileSnapshotStore needs a transport only for its legacy peer encoding.
	_, transport := raft.NewInmemTransport("")
	defer transport.Close()
	meta := checkpoint.Meta
	sink, err := snapshots.Create(meta.Version, meta.Index, meta.Term, meta.Configuration, meta.ConfigurationIndex, transport)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	if _, err := sink.Write(checkpoint.State); err != nil {
		_ = sink.Cancel()
		return CheckpointImportResult{}, err
	}
	if err := sink.Close(); err != nil {
		return CheckpointImportResult{}, err
	}
	if err := os.Chmod(filepath.Join(config.DataDir, "snapshots", sink.ID()), 0o700); err != nil {
		return CheckpointImportResult{}, err
	}
	if err := os.Chmod(filepath.Join(config.DataDir, "snapshots", sink.ID(), "state.bin"), 0o600); err != nil {
		return CheckpointImportResult{}, err
	}
	floor, err := store.prepareReplay(true)
	if err != nil {
		return CheckpointImportResult{}, err
	}
	return CheckpointImportResult{SnapshotIndex: meta.Index, RevisionFloor: floor, BackupFile: backupPath}, nil
}
