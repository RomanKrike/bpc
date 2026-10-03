package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

type delayedRecoveryFSM struct {
	raft.FSM
	enabled atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (f *delayedRecoveryFSM) Apply(log *raft.Log) interface{} {
	var command Mutation
	_ = json.Unmarshal(log.Data, &command)
	if command.Kind == "ReconcileRevision" && f.enabled.CompareAndSwap(true, false) {
		close(f.entered)
		<-f.release
	}
	return f.FSM.Apply(log)
}

func TestRecoveryLeaderLossAfterCommitIsRetryable(t *testing.T) {
	var nodes []*testRaftNode
	var delays []*delayedRecoveryFSM
	for _, id := range []string{"recovery-a", "recovery-b", "recovery-c"} {
		wrapper := &delayedRecoveryFSM{entered: make(chan struct{}), release: make(chan struct{})}
		node := newTestRaftNode(t, id, func(fsm raft.FSM) raft.FSM { wrapper.FSM = fsm; return wrapper })
		nodes = append(nodes, node)
		delays = append(delays, wrapper)
	}
	defer func() {
		for _, node := range nodes {
			_ = node.raft.Shutdown().Error()
			_ = node.store.Close()
		}
	}()
	var servers []raft.Server
	for _, node := range nodes {
		servers = append(servers, raft.Server{ID: raft.ServerID(node.id), Address: raft.ServerAddress(node.id), Suffrage: raft.Voter})
		for _, peer := range nodes {
			if peer != node {
				node.transport.Connect(raft.ServerAddress(peer.id), peer.transport)
			}
		}
	}
	if err := nodes[0].raft.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil {
		t.Fatal(err)
	}
	leader := waitLeader(t, nodes, 2*time.Second)
	admin := &Node{config: NodeConfig{NodeID: leader.id}, raft: leader.raft, fsm: leader.fsm, store: leader.store}
	path := "control/access/device-d1.json"
	result, err := admin.Submit(Mutation{Version: 1, ID: "revoke", Kind: "Access", Operations: []Operation{{Op: "put", Path: path, Data: []byte("revoke")}}}, time.Second)
	if err != nil || !result.OK {
		t.Fatal(result, err)
	}
	view, err := admin.RecoveryState(0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var delay *delayedRecoveryFSM
	var survivors []*testRaftNode
	for i, node := range nodes {
		if node == leader {
			delay = delays[i]
		} else {
			survivors = append(survivors, node)
		}
	}
	delay.enabled.Store(true)
	defer func() {
		select {
		case <-delay.release:
		default:
			close(delay.release)
		}
	}()
	finished := make(chan error, 1)
	go func() { _, err := admin.ReconcileRevision(view, 1000, 2*time.Second); finished <- err }()
	select {
	case <-delay.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery was not committed")
	}
	// The entry has reached quorum, but the old leader has not completed Apply
	// or sent a successful response. Lose it at exactly that boundary.
	leader.transport.DisconnectAll()
	for _, peer := range survivors {
		peer.transport.Disconnect(raft.ServerAddress(leader.id))
	}
	newLeader := waitLeader(t, survivors, 3*time.Second)
	close(delay.release)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("lost leader acknowledged recovery")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not return")
	}
	retry := &Node{config: NodeConfig{NodeID: newLeader.id}, raft: newLeader.raft, fsm: newLeader.fsm, store: newLeader.store}
	current, err := retry.RecoveryState(0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 1000 || current.Digest != view.Digest {
		t.Fatalf("committed state changed: %+v", current)
	}
	result, err = retry.ReconcileRevision(current, 1000, time.Second)
	if err != nil || !result.OK || result.Revision != 1000 {
		t.Fatal("retry inflated revision", result, err)
	}
	for _, node := range survivors {
		if raw, err := os.ReadFile(filepath.Join(node.root, path)); err != nil || string(raw) != "revoke" {
			t.Fatal("policy changed", err)
		}
	}
	// A stale proposal must not overwrite a newer CAS mutation.
	current, err = retry.RecoveryState(0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err = retry.Submit(Mutation{Version: 1, ID: "cas", Kind: "Access", Operations: []Operation{{Op: "put", Path: path, Data: []byte("deny"), ExpectedSHA256: sha256Hex([]byte("revoke"))}}}, time.Second)
	if err != nil || !result.OK {
		t.Fatal(result, err)
	}
	if _, err = retry.ReconcileRevision(current, 1001, time.Second); err == nil {
		t.Fatal("stale proposal accepted")
	}
}

func TestRecoveryPreservesFloorAndRejectsNormalMutationBypass(t *testing.T) {
	n := newTestRaftNode(t, "floor")
	defer func() { _ = n.raft.Shutdown().Error(); _ = n.store.Close() }()
	if err := n.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: "floor", Address: "floor", Suffrage: raft.Voter}}}).Error(); err != nil {
		t.Fatal(err)
	}
	waitLeader(t, []*testRaftNode{n}, time.Second)
	if err := n.store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(keyRevisionFloor, u64key(50)) }); err != nil {
		t.Fatal(err)
	}
	node := &Node{config: NodeConfig{NodeID: "floor"}, raft: n.raft, fsm: n.fsm, store: n.store, revisionFloor: 50}
	if _, _, err := node.StrongRead(time.Second); err == nil {
		t.Fatal("floor bypassed")
	}
	if _, err := node.Submit(Mutation{Kind: "ReconcileRevision", RevisionMinimum: 50}, time.Second); err == nil {
		t.Fatal("normal mutation bypassed recovery checks")
	}
	view, err := node.RecoveryState(0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.ReconcileRevision(view, 49, time.Second); err == nil {
		t.Fatal("floor lowered")
	}
	if result, err := node.ReconcileRevision(view, 50, time.Second); err != nil || !result.OK || result.Revision != 50 {
		t.Fatal(result, err)
	}
	if _, _, err := node.StrongRead(time.Second); err != nil {
		t.Fatal(err)
	}
	if floor, err := n.store.revisionFloor(); err != nil || floor != 50 {
		t.Fatal("floor reset", floor, err)
	}
}
