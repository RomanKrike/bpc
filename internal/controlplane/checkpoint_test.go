package controlplane

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func checkpointFixture(t *testing.T) (ReplayCheckpoint, NodeConfig, *Store, *StateMachine) {
	t.Helper()
	dir, root := t.TempDir(), t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "raft-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fsm := NewStateMachine(store, root)
	cert := testMembershipCertificate(t, "checkpoint-cluster", "recipient")
	writeMembershipRecord(t, filepath.Join(root, "cluster/controllers"), "recipient", "voter", cert)
	writeMembershipRecord(t, filepath.Join(root, "cluster/controllers"), "donor", "voter", testMembershipCertificate(t, "checkpoint-cluster", "donor"))
	donor, err := os.ReadFile(filepath.Join(root, "cluster/controllers/donor.json"))
	if err != nil {
		t.Fatal(err)
	}
	membership, err := os.ReadFile(filepath.Join(root, "cluster/controllers/recipient.json"))
	if err != nil {
		t.Fatal(err)
	}
	command := Mutation{Version: CommandVersion, ID: "base", Kind: "Fixture", Operations: []Operation{
		{Op: "put", Path: "cluster/cluster.json", Data: []byte(`{"cluster_id":"checkpoint-cluster"}`)},
		{Op: "put", Path: "cluster/controllers/recipient.json", Data: membership},
		{Op: "put", Path: "cluster/controllers/donor.json", Data: donor},
		{Op: "put", Path: "control/access/device-d1.json", Data: []byte("revoke")},
	}}
	raw, _ := json.Marshal(command)
	if result := fsm.Apply(&raft.Log{Index: 2, Data: raw}).(MutationResult); !result.OK {
		t.Fatal(result)
	}
	state, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	eraseReplayIndex(t, store)
	checkpoint := ReplayCheckpoint{Version: 1, ClusterID: "checkpoint-cluster", SourceNodeID: "donor", State: state, Meta: raft.SnapshotMeta{
		Version: raft.SnapshotVersionMax, Index: 2, Term: 1, ConfigurationIndex: 1, Size: int64(len(state)),
		Configuration: raft.Configuration{Servers: []raft.Server{{ID: "donor", Address: "donor", Suffrage: raft.Voter}, {ID: "recipient", Address: "recipient", Suffrage: raft.Voter}}},
	}}
	checkpoint.SHA256 = checkpointChecksum(checkpoint)
	config := NodeConfig{NodeID: "recipient", RaftAddress: "recipient", DataDir: dir, StateRoot: root, TLS: TLSMaterial{ClusterID: "checkpoint-cluster"}}
	return checkpoint, config, store, fsm
}

func TestCheckpointImportPreservesLegacyDBAndCreatesRealReplayBase(t *testing.T) {
	checkpoint, config, store, fsm := checkpointFixture(t)
	before, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	result, err := installReplayCheckpoint(store, config, checkpoint, testMembershipCertificate(t, config.TLS.ClusterID, config.NodeID), testMembershipCertificate(t, "checkpoint-cluster", "donor"))
	if err != nil {
		t.Fatal(err)
	}
	if result.SnapshotIndex != 2 || result.RevisionFloor != 1 {
		t.Fatalf("bad import: %+v", result)
	}
	after, err := fsm.ExportSnapshot()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("import changed current canonical state: %v", err)
	}
	backup, err := OpenStore(result.BackupFile)
	if err != nil {
		t.Fatal(err)
	}
	backed, err := NewStateMachine(backup, t.TempDir()).ExportSnapshot()
	backup.Close()
	if err != nil || !bytes.Equal(before, backed) {
		t.Fatalf("backup differs: %v", err)
	}
	info, err := os.Stat(result.BackupFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
	snapshots, err := raft.NewFileSnapshotStore(config.DataDir, 3, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	available, err := snapshots.List()
	if err != nil || len(available) != 1 {
		t.Fatalf("snapshot missing: %v %v", available, err)
	}
	// Actual Raft must accept the installed index/term/configuration and state.
	_, transport := raft.NewInmemTransport("recipient")
	defer transport.Close()
	raftConfig := raft.DefaultConfig()
	raftConfig.LocalID = "recipient"
	raftConfig.LogOutput = io.Discard
	instance, err := raft.NewRaft(raftConfig, fsm, store, store, snapshots, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = instance.Shutdown().Error() }()
	if instance.AppliedIndex() != 2 {
		t.Fatalf("wrong restored index %d", instance.AppliedIndex())
	}
	if fsm.Revision() != 1 {
		t.Fatalf("wrong restored revision %d", fsm.Revision())
	}
	if _, err := installReplayCheckpoint(store, config, checkpoint, testMembershipCertificate(t, config.TLS.ClusterID, config.NodeID), testMembershipCertificate(t, "checkpoint-cluster", "donor")); err == nil {
		t.Fatal("equal checkpoint replaced")
	}
}

func TestCheckpointRejectsUntrustedOrMismatchedMetadataWithoutWrites(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ReplayCheckpoint, *NodeConfig)
		reseal bool
	}{
		{"checksum", func(c *ReplayCheckpoint, _ *NodeConfig) { c.Meta.Index++ }, false},
		{"cluster", func(c *ReplayCheckpoint, _ *NodeConfig) { c.ClusterID = "foreign" }, true},
		{"index", func(c *ReplayCheckpoint, _ *NodeConfig) { c.Meta.Index = 0 }, true},
		{"configuration-index", func(c *ReplayCheckpoint, _ *NodeConfig) { c.Meta.ConfigurationIndex = c.Meta.Index + 1 }, true},
		{"size", func(c *ReplayCheckpoint, _ *NodeConfig) { c.Meta.Size++ }, true},
		{"address", func(_ *ReplayCheckpoint, n *NodeConfig) { n.RaftAddress = "wrong" }, true},
		{"recipient-missing", func(c *ReplayCheckpoint, _ *NodeConfig) {
			c.Meta.Configuration.Servers = c.Meta.Configuration.Servers[:1]
		}, true},
		{"source-not-voter", func(c *ReplayCheckpoint, _ *NodeConfig) { c.Meta.Configuration.Servers[0].Suffrage = raft.Nonvoter }, true},
		{"certificate", func(_ *ReplayCheckpoint, n *NodeConfig) { n.NodeID = "different" }, true},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			checkpoint, config, store, fsm := checkpointFixture(t)
			before, _ := fsm.ExportSnapshot()
			scenario.change(&checkpoint, &config)
			if scenario.reseal {
				checkpoint.SHA256 = checkpointChecksum(checkpoint)
			}
			if _, err := installReplayCheckpoint(store, config, checkpoint, testMembershipCertificate(t, "checkpoint-cluster", "recipient"), testMembershipCertificate(t, "checkpoint-cluster", "donor")); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
			after, err := fsm.ExportSnapshot()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected import changed DB: %v", err)
			}
			if _, err := os.Stat(filepath.Join(config.DataDir, "snapshots")); !os.IsNotExist(err) {
				t.Fatalf("rejected import created snapshot files: %v", err)
			}
			if _, err := os.Stat(filepath.Join(config.DataDir, "replay-backups")); !os.IsNotExist(err) {
				t.Fatalf("rejected import wrote a backup: %v", err)
			}
		})
	}
}

func TestCheckpointImportKeepsHigherHistoricalRevisionFloor(t *testing.T) {
	checkpoint, config, store, fsm := checkpointFixture(t)
	indexedMutation(t, fsm, 3, "newer")
	indexedMutation(t, fsm, 4, "revoke")
	eraseReplayIndex(t, store)
	result, err := installReplayCheckpoint(store, config, checkpoint, testMembershipCertificate(t, config.TLS.ClusterID, config.NodeID), testMembershipCertificate(t, "checkpoint-cluster", "donor"))
	if err != nil || result.RevisionFloor != 3 {
		t.Fatalf("lost floor: %+v %v", result, err)
	}
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(checkpoint.State))); err != nil {
		t.Fatal(err)
	}
	node := &Node{fsm: fsm, revisionFloor: result.RevisionFloor}
	if node.checkRevisionFloor() == nil {
		t.Fatal("older imported base permitted revision rollback")
	}
}

func TestCheckpointExportUsesRaftSnapshotMetadata(t *testing.T) {
	n := newTestRaftNode(t, "source")
	defer func() { _ = n.raft.Shutdown().Error(); _ = n.store.Close() }()
	if err := n.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: "source", Address: "source", Suffrage: raft.Voter}}}).Error(); err != nil {
		t.Fatal(err)
	}
	waitLeader(t, []*testRaftNode{n}, time.Second)
	applyMutation(t, n, Mutation{Version: CommandVersion, ID: "cluster", Kind: "Fixture", Operations: []Operation{{Op: "put", Path: "cluster/cluster.json", Data: []byte(`{"cluster_id":"checkpoint-cluster"}`)}}})
	node := &Node{config: NodeConfig{NodeID: n.id}, raft: n.raft, fsm: n.fsm, snapshots: n.snapshots}
	checkpoint, err := node.ExportReplayCheckpoint(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	meta, reader, err := n.snapshots.Open(checkpoint.Meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(raw, checkpoint.State) || meta.Index != checkpoint.Meta.Index || meta.Term != checkpoint.Meta.Term || checkpoint.SHA256 != checkpointChecksum(checkpoint) {
		t.Fatalf("checkpoint not paired with Raft snapshot: %v", err)
	}
}

func TestCheckpointRejectsCanonicalCertificateRevocation(t *testing.T) {
	for _, nodeID := range []string{"recipient", "donor"} {
		t.Run(nodeID, func(t *testing.T) {
			checkpoint, config, store, fsm := checkpointFixture(t)
			before, _ := fsm.ExportSnapshot()
			var envelope snapshotEnvelope
			if err := json.Unmarshal(checkpoint.State, &envelope); err != nil {
				t.Fatal(err)
			}
			path := "cluster/controllers/" + nodeID + ".json"
			var record membershipRecord
			if err := json.Unmarshal(envelope.Entries[path], &record); err != nil {
				t.Fatal(err)
			}
			record.State = "revoked"
			envelope.Entries[path], _ = json.Marshal(record)
			envelope.Checksum = snapshotChecksum(envelope.SchemaVersion, envelope.Revision, envelope.Entries)
			checkpoint.State, _ = json.Marshal(envelope)
			checkpoint.Meta.Size = int64(len(checkpoint.State))
			checkpoint.SHA256 = checkpointChecksum(checkpoint)
			if _, err := installReplayCheckpoint(store, config, checkpoint, testMembershipCertificate(t, "checkpoint-cluster", "recipient"), testMembershipCertificate(t, "checkpoint-cluster", "donor")); err == nil {
				t.Fatal("revoked certificate accepted")
			}
			after, err := fsm.ExportSnapshot()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected checkpoint changed policy")
			}
			if _, err := os.Stat(filepath.Join(config.DataDir, "snapshots")); !os.IsNotExist(err) {
				t.Fatal("rejected checkpoint wrote snapshots")
			}
		})
	}
}
