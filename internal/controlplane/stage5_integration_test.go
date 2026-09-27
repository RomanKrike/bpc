package controlplane

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func connectTestCluster(nodes []*testRaftNode) {
	for _, left := range nodes {
		for _, right := range nodes {
			if left != right {
				left.transport.Connect(raft.ServerAddress(right.id), right.transport)
			}
		}
	}
}

func disconnectTestNode(target *testRaftNode, nodes []*testRaftNode) {
	for _, peer := range nodes {
		if peer == target {
			continue
		}
		target.transport.Disconnect(raft.ServerAddress(peer.id))
		peer.transport.Disconnect(raft.ServerAddress(target.id))
	}
}

func applyMutation(t *testing.T, node *testRaftNode, command Mutation) MutationResult {
	t.Helper()
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	future := node.raft.Apply(raw, 2*time.Second)
	if err := future.Error(); err != nil {
		t.Fatal(err)
	}
	result, ok := future.Response().(MutationResult)
	if !ok {
		t.Fatalf("unexpected mutation response %T", future.Response())
	}
	if !result.OK {
		t.Fatalf("mutation failed: %+v", result)
	}
	return result
}

func TestFollowerCatchUpAfterSnapshot(t *testing.T) {
	nodes := []*testRaftNode{
		newTestRaftNode(t, "a"),
		newTestRaftNode(t, "b"),
		newTestRaftNode(t, "c"),
	}
	defer func() {
		for _, node := range nodes {
			if node.raft != nil {
				_ = node.raft.Shutdown().Error()
			}
			if node.store != nil {
				_ = node.store.Close()
			}
		}
	}()
	connectTestCluster(nodes)
	configuration := raft.Configuration{Servers: []raft.Server{
		{ID: "a", Address: "a", Suffrage: raft.Voter},
		{ID: "b", Address: "b", Suffrage: raft.Voter},
		{ID: "c", Address: "c", Suffrage: raft.Voter},
	}}
	if err := nodes[0].raft.BootstrapCluster(configuration).Error(); err != nil {
		t.Fatal(err)
	}
	leader := waitLeader(t, nodes, 3*time.Second)

	var lagging *testRaftNode
	for _, node := range nodes {
		if node != leader {
			lagging = node
			break
		}
	}
	if lagging == nil {
		t.Fatal("missing follower")
	}
	disconnectTestNode(lagging, nodes)

	applyMutation(t, leader, Mutation{
		Version:  CommandVersion,
		ID:       "cluster-metadata",
		Kind:     "BootstrapClusterMetadata",
		IssuedAt: 1,
		Operations: []Operation{{
			Op:   "put",
			Path: "cluster/cluster.json",
			Data: []byte(`{"cluster_id":"test-cluster","version":1}`),
		}},
	})
	for index := 0; index < 40; index++ {
		applyMutation(t, leader, Mutation{
			Version:  CommandVersion,
			ID:       fmt.Sprintf("mutation-%d", index),
			Kind:     "CatchUpMutation",
			IssuedAt: int64(10 + index),
			Operations: []Operation{{
				Op:   "put",
				Path: "control/access/device-d1.json",
				Data: []byte(fmt.Sprintf(`{"revision":%d}`, index)),
			}},
		})
	}
	if err := leader.raft.Snapshot().Error(); err != nil {
		t.Fatal(err)
	}

	connectTestCluster(nodes)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		revision, err := lagging.store.revision()
		if err == nil && revision == 41 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	revision, _ := lagging.store.revision()
	t.Fatalf("lagging follower did not catch up: revision=%d want=41", revision)
}

func TestQuorumRestoresAfterNetworkPartition(t *testing.T) {
	nodes := []*testRaftNode{
		newTestRaftNode(t, "a"),
		newTestRaftNode(t, "b"),
		newTestRaftNode(t, "c"),
	}
	defer func() {
		for _, node := range nodes {
			if node.raft != nil {
				_ = node.raft.Shutdown().Error()
			}
			if node.store != nil {
				_ = node.store.Close()
			}
		}
	}()
	connectTestCluster(nodes)
	configuration := raft.Configuration{Servers: []raft.Server{
		{ID: "a", Address: "a", Suffrage: raft.Voter},
		{ID: "b", Address: "b", Suffrage: raft.Voter},
		{ID: "c", Address: "c", Suffrage: raft.Voter},
	}}
	if err := nodes[0].raft.BootstrapCluster(configuration).Error(); err != nil {
		t.Fatal(err)
	}
	oldLeader := waitLeader(t, nodes, 3*time.Second)
	disconnectTestNode(oldLeader, nodes)

	raw, _ := json.Marshal(Mutation{
		Version:  CommandVersion,
		ID:       "partitioned",
		Kind:     "PartitionedMutation",
		IssuedAt: 100,
		Operations: []Operation{{
			Op:   "put",
			Path: "control/access/device-d1.json",
			Data: []byte(`{"allow":[]}`),
		}},
	})
	future := oldLeader.raft.Apply(raw, 500*time.Millisecond)
	if err := future.Error(); err == nil {
		t.Fatal("isolated Controller committed without quorum")
	}

	connectTestCluster(nodes)
	leader := waitLeader(t, nodes, 4*time.Second)
	result := applyMutation(t, leader, Mutation{
		Version:  CommandVersion,
		ID:       "after-quorum-restore",
		Kind:     "GrantAccess",
		IssuedAt: 200,
		Operations: []Operation{{
			Op:   "put",
			Path: "control/access/device-d1.json",
			Data: []byte(`{"allow":["192.168.88.0/24"]}`),
		}},
	})
	if result.Revision == 0 {
		t.Fatal("mutation after quorum restoration did not advance revision")
	}
}

func TestLogicalSnapshotRestoreThroughRaft(t *testing.T) {
	node := newTestRaftNode(t, "a")
	defer func() {
		if node.raft != nil {
			_ = node.raft.Shutdown().Error()
		}
		if node.store != nil {
			_ = node.store.Close()
		}
	}()
	configuration := raft.Configuration{Servers: []raft.Server{
		{ID: "a", Address: "a", Suffrage: raft.Voter},
	}}
	if err := node.raft.BootstrapCluster(configuration).Error(); err != nil {
		t.Fatal(err)
	}
	_ = waitLeader(t, []*testRaftNode{node}, 3*time.Second)

	applyMutation(t, node, Mutation{
		Version:  CommandVersion,
		ID:       "cluster",
		Kind:     "ClusterMetadata",
		IssuedAt: 1,
		Operations: []Operation{{
			Op:   "put",
			Path: "cluster/cluster.json",
			Data: []byte(`{"cluster_id":"restore-cluster","version":1}`),
		}},
	})
	applyMutation(t, node, Mutation{
		Version:  CommandVersion,
		ID:       "old-user",
		Kind:     "CreateUser",
		IssuedAt: 2,
		Operations: []Operation{{
			Op:   "put",
			Path: "control/identity/users/u1.json",
			Data: []byte(`{"id":"u1","enabled":true}`),
		}},
	})
	fsm := NewStateMachine(node.store, node.root)
	backup, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if clusterID, err := SnapshotClusterID(backup); err != nil || clusterID != "restore-cluster" {
		t.Fatalf("snapshot cluster id=%q err=%v", clusterID, err)
	}

	applyMutation(t, node, Mutation{
		Version:  CommandVersion,
		ID:       "disable-user",
		Kind:     "DisableUser",
		IssuedAt: 3,
		Operations: []Operation{{
			Op:   "put",
			Path: "control/identity/users/u1.json",
			Data: []byte(`{"id":"u1","enabled":false}`),
		}},
	})

	wrapper := &Node{raft: node.raft, fsm: fsm}
	if err := wrapper.RestoreSnapshot(backup, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	value, ok, err := node.store.canonicalGet("control/identity/users/u1.json")
	if err != nil || !ok {
		t.Fatalf("restored user missing: ok=%v err=%v", ok, err)
	}
	if string(value) != `{"id":"u1","enabled":true}` {
		t.Fatalf("unexpected restored user: %s", value)
	}
}
