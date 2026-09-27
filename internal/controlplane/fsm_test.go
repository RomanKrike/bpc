package controlplane

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
)

func testFSM(t *testing.T) (*Store, *StateMachine, string) {
	t.Helper()
	root := t.TempDir()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, NewStateMachine(store, root), root
}

func applyForTest(t *testing.T, fsm *StateMachine, command Mutation) MutationResult {
	t.Helper()
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := fsm.Apply(&raft.Log{Data: raw}).(MutationResult)
	if !ok {
		t.Fatalf("unexpected response type")
	}
	return result
}

func TestStateMachineAppliesDeterministicCanonicalMutation(t *testing.T) {
	_, fsm, root := testFSM(t)
	command := Mutation{Version: CommandVersion, ID: "m1", Kind: "CreateUser", IssuedAt: 100,
		Operations: []Operation{{Op: "put", Path: "control/identity/users/u1.json", Data: []byte(`{"id":"u1","created_at":100}`), IfAbsent: true}}}
	result := applyForTest(t, fsm, command)
	if !result.OK || result.Revision != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	raw, err := os.ReadFile(filepath.Join(root, "control", "identity", "users", "u1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"id":"u1","created_at":100}` {
		t.Fatalf("unexpected projection: %s", raw)
	}

	duplicate := applyForTest(t, fsm, command)
	if !duplicate.Conflict || duplicate.Revision != 1 {
		t.Fatalf("expected deterministic conflict: %+v", duplicate)
	}
}

func TestStateMachineRejectsExternalOrRuntimePaths(t *testing.T) {
	_, fsm, _ := testFSM(t)
	for _, path := range []string{"../etc/passwd", "control/downloads/file.exe", "runtime/secret.json", "transports/wg.key"} {
		result := applyForTest(t, fsm, Mutation{Version: CommandVersion, ID: "x", Kind: "Bad", Operations: []Operation{{Op: "put", Path: path, Data: []byte("x")}}})
		if result.OK || result.Error == "" {
			t.Fatalf("path %q should be rejected: %+v", path, result)
		}
	}
}

type memorySink struct {
	bytes.Buffer
	id        string
	cancelled bool
}

func (m *memorySink) ID() string    { return m.id }
func (m *memorySink) Cancel() error { m.cancelled = true; return nil }
func (m *memorySink) Close() error  { return nil }

func TestSnapshotIsChecksummedAndRestoresProjection(t *testing.T) {
	_, fsm, _ := testFSM(t)
	result := applyForTest(t, fsm, Mutation{Version: CommandVersion, ID: "m1", Kind: "GrantAccess", Operations: []Operation{{Op: "put", Path: "control/access/user-u1.json", Data: []byte(`{"allow":["192.168.88.0/24"]}`)}}})
	if !result.OK {
		t.Fatal(result.Error)
	}
	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memorySink{id: "s1"}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}

	_, restored, root := testFSM(t)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "control", "access", "user-u1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"allow":["192.168.88.0/24"]}` {
		t.Fatalf("unexpected restored data: %s", raw)
	}
}
