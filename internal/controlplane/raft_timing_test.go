package controlplane

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func wanTestConfig(id string) NodeConfig {
	return NodeConfig{NodeID: id, SnapshotThreshold: 64, SnapshotInterval: 30 * time.Second,
		RaftHeartbeatTimeout:   DefaultRaftHeartbeatTimeout,
		RaftElectionTimeout:    DefaultRaftElectionTimeout,
		RaftLeaderLeaseTimeout: DefaultRaftLeaderLeaseTimeout}
}

func TestInvalidRaftTimingDoesNotTouchPersistentState(t *testing.T) {
	for _, change := range []func(*NodeConfig){
		func(c *NodeConfig) { c.RaftLeaderLeaseTimeout = 4 * time.Second },
		func(c *NodeConfig) { c.RaftElectionTimeout = time.Second },
		func(c *NodeConfig) { c.RaftHeartbeatTimeout = -time.Second },
	} {
		c := wanTestConfig("invalid")
		c.RaftAddress = "127.0.0.1:1"
		c.DataDir = filepath.Join(t.TempDir(), "untouched")
		change(&c)
		if n, err := NewNode(c); err == nil {
			_ = n.Shutdown()
			t.Fatal("accepted invalid timing")
		}
		if _, err := os.Stat(c.DataDir); !os.IsNotExist(err) {
			t.Fatalf("invalid config touched data directory: %v", err)
		}
	}
}

// Delay both replication and heartbeat acknowledgements. Disable pipelines so
// every AppendEntries goes through the same fault injector.
type delayedRaftTransport struct {
	*raft.InmemTransport
	delay        atomic.Int64
	delayedCalls atomic.Int64
}

func (d *delayedRaftTransport) AppendEntries(id raft.ServerID, target raft.ServerAddress, request *raft.AppendEntriesRequest, response *raft.AppendEntriesResponse) error {
	if delay := time.Duration(d.delay.Load()); delay > 0 {
		d.delayedCalls.Add(1)
		time.Sleep(delay)
	}
	return d.InmemTransport.AppendEntries(id, target, request, response)
}

func (d *delayedRaftTransport) AppendEntriesPipeline(raft.ServerID, raft.ServerAddress) (raft.AppendPipeline, error) {
	return nil, errors.New("pipeline disabled for delayed RPC test")
}

func TestWANTimingToleratesDelayedAcknowledgementsAndRejectsPartitionWrites(t *testing.T) {
	var nodes []*raft.Raft
	var transports []*delayedRaftTransport
	defer func() {
		for _, n := range nodes {
			_ = n.Shutdown().Error()
		}
	}()
	for _, id := range []string{"wan-a", "wan-b"} {
		c, err := raftRuntimeConfig(wanTestConfig(id))
		if err != nil {
			t.Fatal(err)
		}
		_, inner := raft.NewInmemTransportWithTimeout(raft.ServerAddress(id), 5*time.Second)
		transport := &delayedRaftTransport{InmemTransport: inner}
		store := raft.NewInmemStore()
		n, err := raft.NewRaft(c, &timingFSM{}, store, store, raft.NewInmemSnapshotStore(), transport)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
		transports = append(transports, transport)
	}
	transports[0].Connect("wan-b", transports[1].InmemTransport)
	transports[1].Connect("wan-a", transports[0].InmemTransport)
	if err := nodes[0].BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: "wan-a", Address: "wan-a", Suffrage: raft.Voter}}}).Error(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for nodes[0].State() != raft.Leader && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if nodes[0].State() != raft.Leader {
		t.Fatal("initial leader election timed out")
	}
	if err := nodes[0].AddVoter("wan-b", "wan-b", 0, 8*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if err := nodes[0].Apply([]byte("initial"), 5*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	term := nodes[0].Stats()["term"]
	// Exceeds the previous 500ms leader lease. Wait for multiple delayed RPCs,
	// verifying actual writes as well as leadership through the delay.
	for _, d := range transports {
		d.delay.Store(int64(650 * time.Millisecond))
	}
	for i := 0; i < 6; i++ {
		if err := nodes[0].Apply([]byte("delayed"), 5*time.Second).Error(); err != nil {
			t.Fatalf("delayed write failed: %v", err)
		}
		time.Sleep(400 * time.Millisecond)
		if nodes[0].State() != raft.Leader || nodes[0].Stats()["term"] != term {
			t.Fatal("healthy delayed link caused an election")
		}
	}
	if transports[0].delayedCalls.Load() < 6 {
		t.Fatal("delay injector was not exercised")
	}
	// Real loss of the only other voter must revoke leadership and cannot
	// acknowledge another write. No reduction of quorum or durability settings.
	transports[0].DisconnectAll()
	transports[1].DisconnectAll()
	if err := nodes[0].Apply([]byte("partitioned"), time.Second).Error(); err == nil {
		t.Fatal("partitioned leader acknowledged a write")
	}
	deadline = time.Now().Add(5 * time.Second)
	for nodes[0].State() == raft.Leader && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if nodes[0].State() == raft.Leader {
		t.Fatal("leader did not relinquish role after quorum loss")
	}
	if err := nodes[0].Barrier(time.Second).Error(); err == nil {
		t.Fatal("partitioned node accepted a strong read")
	}
}

type timingFSM struct{}

func (*timingFSM) Apply(*raft.Log) interface{} { return nil }
func (*timingFSM) Snapshot() (raft.FSMSnapshot, error) {
	return nil, errors.New("snapshots unused in timing test")
}
func (*timingFSM) Restore(io.ReadCloser) error { return nil }
