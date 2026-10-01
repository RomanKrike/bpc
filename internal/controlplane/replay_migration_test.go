package controlplane

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

func eraseReplayIndex(t *testing.T, store *Store) {
	t.Helper()
	if err := store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Delete(keyAppliedIndex) }); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyReplayWithoutSnapshotPreservesStateAndRefusesStartup(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "raft-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	fsm := NewStateMachine(store, root)
	indexedMutation(t, fsm, 1, "grant")
	indexedMutation(t, fsm, 2, "revoke")
	eraseReplayIndex(t, store)
	before, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// No TLS material is needed: refusal must happen before listeners or Raft
	// are started, and must release the Bolt lock for safe recovery/inspection.
	node, err := NewNode(NodeConfig{NodeID: "legacy", RaftAddress: "127.0.0.1:0", DataDir: dir, StateRoot: root})
	if node != nil || !errors.Is(err, ErrLegacyReplayUnsafe) {
		t.Fatalf("unsafe startup: node=%v err=%v", node, err)
	}
	store, err = OpenStore(filepath.Join(dir, "raft-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	after, err := NewStateMachine(store, root).ExportSnapshot()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("canonical state changed on refusal: %v", err)
	}
	projected, err := os.ReadFile(filepath.Join(root, "control/access/device-d1.json"))
	if err != nil || string(projected) != "revoke" {
		t.Fatalf("projection changed: %q %v", projected, err)
	}
	if err := store.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketMeta).Get(keyRevisionFloor) != nil {
			t.Fatal("failed preflight changed migration metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReplayPreflightAcceptsFreshAndIndexedStores(t *testing.T) {
	store, fsm, _ := testFSM(t)
	if floor, err := store.prepareReplay(false); err != nil || floor != 0 {
		t.Fatalf("fresh: %d %v", floor, err)
	}
	indexedMutation(t, fsm, 1, "revoke")
	if floor, err := store.prepareReplay(false); err != nil || floor != 1 {
		t.Fatalf("indexed: %d %v", floor, err)
	}
}

func TestReplayPreflightRejectsMalformedWatermark(t *testing.T) {
	store, fsm, _ := testFSM(t)
	indexedMutation(t, fsm, 1, "revoke")
	if err := store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(keyAppliedIndex, []byte{1}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.prepareReplay(true); err == nil {
		t.Fatal("malformed watermark accepted")
	}
}

func TestLegacySnapshotRetainsRevisionFloorAcrossFailedMigrationRestarts(t *testing.T) {
	store, fsm, _ := testFSM(t)
	indexedMutation(t, fsm, 1, "snapshot-policy")
	snapshot, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	indexedMutation(t, fsm, 2, "revoke")
	eraseReplayIndex(t, store)
	// Model a historical counter inflated by replay before this update.
	if err := store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(keyRevision, u64key(50)) }); err != nil {
		t.Fatal(err)
	}
	floor, err := store.prepareReplay(true)
	if err != nil || floor != 50 {
		t.Fatalf("legacy snapshot: %d %v", floor, err)
	}
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(snapshot))); err != nil {
		t.Fatal(err)
	}
	indexedMutation(t, fsm, 2, "revoke")
	if fsm.Revision() != 2 {
		t.Fatalf("wrong reconstructed revision %d", fsm.Revision())
	}
	// Another process restart cannot overwrite the original 50 with the lower
	// reconstructed 2, including after a restore interrupted by quorum loss.
	floor, err = store.prepareReplay(true)
	if err != nil || floor != 50 {
		t.Fatalf("floor lost: %d %v", floor, err)
	}
	node := &Node{fsm: fsm, revisionFloor: floor}
	if node.checkRevisionFloor() == nil {
		t.Fatal("revision rollback accepted")
	}
	if _, err := node.ExportSnapshot(); err == nil {
		t.Fatal("lower revision exported")
	}
	if _, err := fsm.ExportSnapshot(); err == nil {
		t.Fatal("lower revision exported directly by FSM")
	}
	// Automatic Raft snapshots bypass Node.Snapshot and call the FSM directly.
	if _, err := fsm.Snapshot(); err == nil {
		t.Fatal("automatic snapshot persisted an unreconciled revision")
	}
}

func TestRevisionFloorBlocksSuccessfulControllerOperations(t *testing.T) {
	n := newTestRaftNode(t, "floor-test")
	defer func() { _ = n.raft.Shutdown().Error(); _ = n.store.Close() }()
	if err := n.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: "floor-test", Address: "floor-test", Suffrage: raft.Voter}}}).Error(); err != nil {
		t.Fatal(err)
	}
	waitLeader(t, []*testRaftNode{n}, time.Second)
	node := &Node{raft: n.raft, fsm: n.fsm, revisionFloor: 10}
	if _, _, err := node.StrongRead(time.Second); err == nil {
		t.Fatal("lower-revision strong read succeeded")
	}
	if _, err := node.Submit(Mutation{Version: CommandVersion, ID: "forbidden", Kind: "Test", Operations: []Operation{{Op: "put", Path: "control/access/device-d1.json", Data: []byte("grant")}}}, time.Second); err == nil {
		t.Fatal("lower-revision write succeeded")
	}
	if err := node.WaitApplied(n.raft.AppliedIndex(), time.Second); err == nil {
		t.Fatal("lower-revision follower acknowledgement succeeded")
	}
	if err := node.AddMember("b", "b", false, time.Second); err == nil {
		t.Fatal("lower-revision membership change succeeded")
	}
	if err := node.RemoveMember("floor-test", true, time.Second); err == nil {
		t.Fatal("lower-revision member removal succeeded")
	}
	if err := node.Snapshot(); err == nil {
		t.Fatal("lower-revision snapshot persisted")
	}
	if n.fsm.Revision() != 0 {
		t.Fatal("refused operations changed revision")
	}
	if _, exists, err := n.store.canonicalGet("control/access/device-d1.json"); err != nil || exists {
		t.Fatalf("refused write changed policy: %v %v", exists, err)
	}
}
