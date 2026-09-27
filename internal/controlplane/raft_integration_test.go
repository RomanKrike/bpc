package controlplane

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

type testRaftNode struct {
	id        string
	root      string
	raft      *raft.Raft
	transport *raft.InmemTransport
	store     *Store
}

func newTestRaftNode(t *testing.T, id string) *testRaftNode {
	t.Helper()
	root := t.TempDir()
	canonical, err := OpenStore(filepath.Join(t.TempDir(), id+".db"))
	if err != nil {
		t.Fatal(err)
	}
	fsm := NewStateMachine(canonical, root)
	logs := raft.NewInmemStore()
	stable := raft.NewInmemStore()
	snaps := raft.NewInmemSnapshotStore()
	address, transport := raft.NewInmemTransport(raft.ServerAddress(id))
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(id)
	config.HeartbeatTimeout = 120 * time.Millisecond
	config.ElectionTimeout = 120 * time.Millisecond
	config.LeaderLeaseTimeout = 100 * time.Millisecond
	config.CommitTimeout = 20 * time.Millisecond
	config.SnapshotThreshold = 16
	instance, err := raft.NewRaft(config, fsm, logs, stable, snaps, transport)
	if err != nil {
		t.Fatal(err)
	}
	if string(address) != id {
		t.Fatalf("unexpected address %s", address)
	}
	return &testRaftNode{id: id, root: root, raft: instance, transport: transport, store: canonical}
}

func waitLeader(t *testing.T, nodes []*testRaftNode, timeout time.Duration) *testRaftNode {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.raft != nil && n.raft.State() == raft.Leader {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	states := map[string]string{}
	for _, n := range nodes {
		if n.raft != nil {
			states[n.id] = n.raft.State().String()
		}
	}
	t.Fatalf("leader election timeout: %+v", states)
	return nil
}

func TestThreeControllerQuorumReplicationAndLeaderFailover(t *testing.T) {
	nodes := []*testRaftNode{newTestRaftNode(t, "a"), newTestRaftNode(t, "b"), newTestRaftNode(t, "c")}
	defer func() {
		for _, n := range nodes {
			if n.raft != nil {
				_ = n.raft.Shutdown().Error()
			}
			if n.store != nil {
				_ = n.store.Close()
			}
		}
	}()
	for _, left := range nodes {
		for _, right := range nodes {
			if left != right {
				left.transport.Connect(raft.ServerAddress(right.id), right.transport)
			}
		}
	}
	config := raft.Configuration{Servers: []raft.Server{{ID: "a", Address: "a", Suffrage: raft.Voter}, {ID: "b", Address: "b", Suffrage: raft.Voter}, {ID: "c", Address: "c", Suffrage: raft.Voter}}}
	if err := nodes[0].raft.BootstrapCluster(config).Error(); err != nil {
		t.Fatal(err)
	}
	leader := waitLeader(t, nodes, 3*time.Second)
	cmd := Mutation{Version: CommandVersion, ID: "create-user", Kind: "CreateUser", IssuedAt: 100, Operations: []Operation{{Op: "put", Path: "control/identity/users/u1.json", Data: []byte(`{"id":"u1"}`)}}}
	raw, _ := json.Marshal(cmd)
	future := leader.raft.Apply(raw, 2*time.Second)
	if err := future.Error(); err != nil {
		t.Fatal(err)
	}
	result := future.Response().(MutationResult)
	if !result.OK {
		t.Fatalf("mutation failed: %+v", result)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, n := range nodes {
			value, ok, err := n.store.canonicalGet("control/identity/users/u1.json")
			if err != nil || !ok || string(value) != `{"id":"u1"}` {
				ready = false
				break
			}
		}
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, n := range nodes {
		value, ok, _ := n.store.canonicalGet("control/identity/users/u1.json")
		if !ok || string(value) != `{"id":"u1"}` {
			t.Fatalf("%s did not replicate user", n.id)
		}
	}

	oldLeaderID := leader.id
	if err := leader.raft.Shutdown().Error(); err != nil {
		t.Fatal(err)
	}
	_ = leader.store.Close()
	leader.raft = nil
	leader.store = nil
	survivors := []*testRaftNode{}
	for _, n := range nodes {
		if n.id != oldLeaderID {
			survivors = append(survivors, n)
		}
	}
	newLeader := waitLeader(t, survivors, 3*time.Second)
	cmd2 := Mutation{Version: CommandVersion, ID: "disable-user", Kind: "DisableUser", IssuedAt: 200, Operations: []Operation{{Op: "put", Path: "control/revocations/user-u1.json", Data: []byte(`{"user_id":"u1","revoked_at":200}`)}}}
	raw2, _ := json.Marshal(cmd2)
	if err := newLeader.raft.Apply(raw2, 2*time.Second).Error(); err != nil {
		t.Fatalf("mutation after leader loss failed: %v", err)
	}

	var other *testRaftNode
	for _, n := range survivors {
		if n != newLeader {
			other = n
		}
	}
	if other == nil {
		t.Fatal("missing survivor")
	}
	if err := other.raft.Shutdown().Error(); err != nil {
		t.Fatal(err)
	}
	_ = other.store.Close()
	other.raft = nil
	other.store = nil
	cmd3 := Mutation{Version: CommandVersion, ID: "no-quorum", Kind: "GrantAccess", IssuedAt: 300, Operations: []Operation{{Op: "put", Path: "control/access/user-u1.json", Data: []byte(`{}`)}}}
	raw3, _ := json.Marshal(cmd3)
	if err := newLeader.raft.Apply(raw3, 350*time.Millisecond).Error(); err == nil {
		t.Fatal("mutation unexpectedly committed without quorum")
	}
}
