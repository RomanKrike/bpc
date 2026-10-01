package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func indexedMutation(t *testing.T, fsm *StateMachine, index uint64, value string) MutationResult {
	t.Helper()
	raw, err := json.Marshal(Mutation{Version: CommandVersion, ID: value, Kind: "ReplayTest", Operations: []Operation{{Op: "put", Path: "control/access/device-d1.json", Data: []byte(value)}}})
	if err != nil {
		t.Fatal(err)
	}
	return fsm.Apply(&raft.Log{Index: index, Data: raw}).(MutationResult)
}

func TestDurableFSMReplayDoesNotReapplyCommittedPolicy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	root := t.TempDir()
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	fsm := NewStateMachine(store, root)
	for index, value := range []string{"grant", "revoke"} {
		if result := indexedMutation(t, fsm, uint64(index+1), value); !result.OK {
			t.Fatal(result)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fsm = NewStateMachine(store, root)
	// An election can replay a prefix before the newer revocation. At every
	// point, the durable policy must remain revoked and its revision unchanged.
	for index, value := range []string{"grant", "revoke"} {
		if result := indexedMutation(t, fsm, uint64(index+1), value); !result.OK {
			t.Fatal(result)
		}
		got, ok, err := store.canonicalGet("control/access/device-d1.json")
		if err != nil || !ok || string(got) != "revoke" || fsm.Revision() != 2 {
			t.Fatalf("replay regressed policy: value=%q revision=%d err=%v", got, fsm.Revision(), err)
		}
		projected, err := os.ReadFile(filepath.Join(root, "control/access/device-d1.json"))
		if err != nil || string(projected) != "revoke" {
			t.Fatalf("historical policy was projected: %q %v", projected, err)
		}
	}
	if result := indexedMutation(t, fsm, 3, "new-policy"); !result.OK || result.Revision != 3 {
		t.Fatal(result)
	}
}

func TestSnapshotRestoreResetsDurableReplayWatermark(t *testing.T) {
	_, fsm, _ := testFSM(t)
	if result := indexedMutation(t, fsm, 2, "snapshot-policy"); !result.OK {
		t.Fatal(result)
	}
	backup, err := fsm.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if result := indexedMutation(t, fsm, 100, "later-policy"); !result.OK {
		t.Fatal(result)
	}
	// Legacy snapshot envelopes do not contain an applied index. Restoring them
	// must discard the old DB watermark so the snapshot's suffix can replay.
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(backup))); err != nil {
		t.Fatal(err)
	}
	if result := indexedMutation(t, fsm, 3, "suffix-policy"); !result.OK || result.Revision != 2 {
		t.Fatal(result)
	}
	got, _, err := fsm.store.canonicalGet("control/access/device-d1.json")
	if err != nil || string(got) != "suffix-policy" {
		t.Fatalf("suffix skipped after restore: %q %v", got, err)
	}
}

func TestRaftRestartPreservesCanonicalRevision(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("snapshot=%v", snapshot), func(t *testing.T) {
			dir, root := t.TempDir(), t.TempDir()
			var store *Store
			var instance *raft.Raft
			var fsm *StateMachine
			start := func() {
				var err error
				store, err = OpenStore(filepath.Join(dir, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				fsm = NewStateMachine(store, root)
				snapshots, err := raft.NewFileSnapshotStore(dir, 2, io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				_, transport := raft.NewInmemTransport("persistent")
				config := raft.DefaultConfig()
				config.LocalID = "persistent"
				config.HeartbeatTimeout = 120 * time.Millisecond
				config.ElectionTimeout = 120 * time.Millisecond
				config.LeaderLeaseTimeout = 100 * time.Millisecond
				config.CommitTimeout = 20 * time.Millisecond
				config.LogOutput = io.Discard
				instance, err = raft.NewRaft(config, fsm, store, store, snapshots, transport)
				if err != nil {
					t.Fatal(err)
				}
			}
			stop := func() {
				if instance != nil {
					if err := instance.Shutdown().Error(); err != nil {
						t.Fatal(err)
					}
					instance = nil
				}
				if store != nil {
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					store = nil
				}
			}
			defer stop()
			start()
			if err := instance.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: "persistent", Address: "persistent", Suffrage: raft.Voter}}}).Error(); err != nil {
				t.Fatal(err)
			}
			wait := func() {
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if instance.State() == raft.Leader {
						if err := instance.Barrier(time.Second).Error(); err == nil {
							return
						}
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("durable node did not recover leadership and replay")
			}
			wait()
			submit := func(value string) {
				node := &Node{raft: instance, fsm: fsm}
				result, err := node.Submit(Mutation{Version: CommandVersion, ID: value, Kind: "DurableTest", Operations: []Operation{{Op: "put", Path: "control/access/device-d1.json", Data: []byte(value)}}}, time.Second)
				if err != nil || !result.OK {
					t.Fatalf("submit: %+v %v", result, err)
				}
			}
			submit("grant")
			if snapshot {
				if err := instance.Snapshot().Error(); err != nil {
					t.Fatal(err)
				}
			}
			submit("revoke")
			for round := 0; round < 3; round++ {
				stop()
				start()
				wait()
				value, ok, err := store.canonicalGet("control/access/device-d1.json")
				if err != nil || !ok || string(value) != "revoke" || fsm.Revision() != 2 {
					t.Fatalf("restart %d: value=%q revision=%d err=%v", round, value, fsm.Revision(), err)
				}
			}
			submit("new-policy")
			if fsm.Revision() != 3 {
				t.Fatalf("new mutation revision=%d", fsm.Revision())
			}
		})
	}
}

func TestDurableReplayDoesNotReevaluateConflict(t *testing.T) {
	store, fsm, _ := testFSM(t)
	if result := indexedMutation(t, fsm, 1, "exists"); !result.OK {
		t.Fatal(result)
	}
	command := Mutation{Version: CommandVersion, ID: "conflict", Kind: "Conflict", Operations: []Operation{{Op: "put", Path: "control/access/device-d1.json", Data: []byte("should-never-exist"), IfAbsent: true}}}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	conflict := &raft.Log{Index: 2, Data: raw}
	if result := fsm.Apply(conflict).(MutationResult); !result.Conflict {
		t.Fatal(result)
	}
	raw, err = json.Marshal(Mutation{Version: CommandVersion, ID: "delete", Kind: "Delete", Operations: []Operation{{Op: "delete", Path: "control/access/device-d1.json"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result := fsm.Apply(&raft.Log{Index: 3, Data: raw}).(MutationResult); !result.OK {
		t.Fatal(result)
	}
	fsm = NewStateMachine(store, fsm.root)
	fsm.Apply(conflict)
	if _, exists, err := store.canonicalGet("control/access/device-d1.json"); err != nil || exists || fsm.Revision() != 2 {
		t.Fatalf("replayed conflict resurrected record: exists=%v revision=%d err=%v", exists, fsm.Revision(), err)
	}
}
