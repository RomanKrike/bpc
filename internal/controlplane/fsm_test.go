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

func siteRouterNode(id string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"node_id":           id,
		"roles":             map[string]bool{"site_router": true},
		"authorized_routes": []string{"192.168.88.0/24"},
	})
	return raw
}

func routeOwnerRecord(owner, cidr string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"version":       2,
		"node_id":       owner,
		"owner_node_id": owner,
		"cidr":          cidr,
	})
	return raw
}

func TestStateMachineEnforcesRouteOwnershipAtomically(t *testing.T) {
	_, fsm, _ := testFSM(t)
	bootstrap := Mutation{
		Version: CommandVersion,
		ID:      "routes-bootstrap",
		Kind:    "TestRoutes",
		Operations: []Operation{
			{Op: "put", Path: "control/nodes/home-01.json", Data: siteRouterNode("home-01")},
			{Op: "put", Path: "control/nodes/home-02.json", Data: siteRouterNode("home-02")},
			{Op: "put", Path: "control/routes/home-01-a.json", Data: routeOwnerRecord("home-01", "192.168.88.0/24")},
		},
	}
	if result := applyForTest(t, fsm, bootstrap); !result.OK {
		t.Fatalf("bootstrap route ownership failed: %+v", result)
	}

	// The same owner may advertise another, even overlapping, canonical prefix.
	sameOwner := applyForTest(t, fsm, Mutation{
		Version: CommandVersion,
		ID:      "same-owner",
		Kind:    "TestRoutes",
		Operations: []Operation{
			{Op: "put", Path: "control/routes/home-01-b.json", Data: routeOwnerRecord("home-01", "192.168.88.0/25")},
		},
	})
	if !sameOwner.OK {
		t.Fatalf("same-owner route was rejected: %+v", sameOwner)
	}

	conflict := applyForTest(t, fsm, Mutation{
		Version: CommandVersion,
		ID:      "cross-owner",
		Kind:    "TestRoutes",
		Operations: []Operation{
			{Op: "put", Path: "control/routes/home-02-a.json", Data: routeOwnerRecord("home-02", "192.168.88.128/25")},
		},
	})
	if !conflict.Conflict {
		t.Fatalf("overlapping different-owner route was accepted: %+v", conflict)
	}

	defaultRoute := applyForTest(t, fsm, Mutation{
		Version: CommandVersion,
		ID:      "default-route",
		Kind:    "TestRoutes",
		Operations: []Operation{
			{Op: "put", Path: "control/routes/default.json", Data: routeOwnerRecord("home-01", "0.0.0.0/0")},
		},
	})
	if !defaultRoute.Conflict {
		t.Fatalf("site-router default route was accepted: %+v", defaultRoute)
	}
}

func TestStateMachineRejectsRouteOwnerWithoutSiteRouterCapability(t *testing.T) {
	_, fsm, _ := testFSM(t)
	nodeRaw, _ := json.Marshal(map[string]any{
		"node_id": "ru-01",
		"roles":   map[string]bool{"gateway": true, "relay": true},
	})
	result := applyForTest(t, fsm, Mutation{
		Version: CommandVersion,
		ID:      "bad-owner",
		Kind:    "TestRoutes",
		Operations: []Operation{
			{Op: "put", Path: "control/nodes/ru-01.json", Data: nodeRaw},
			{Op: "put", Path: "control/routes/ru-01.json", Data: routeOwnerRecord("ru-01", "192.168.88.0/24")},
		},
	})
	if !result.Conflict {
		t.Fatalf("non-site-router route owner was accepted: %+v", result)
	}
}

func TestStateMachineRejectsUnapprovedSiteRoute(t *testing.T) {
	_, fsm, _ := testFSM(t)
	result := applyForTest(t, fsm, Mutation{Version: CommandVersion, ID: "unapproved", Kind: "TestRoutes", Operations: []Operation{
		{Op: "put", Path: "control/nodes/home-01.json", Data: siteRouterNode("home-01")},
		{Op: "put", Path: "control/routes/rogue.json", Data: routeOwnerRecord("home-01", "10.0.0.0/8")},
	}})
	if !result.Conflict {
		t.Fatalf("unapproved CIDR committed: %+v", result)
	}
}

func TestStaleHeartbeatCannotOverwriteControllerRouteGrant(t *testing.T) {
	_, fsm, root := testFSM(t)
	path := "control/nodes/home-01.json"
	old := siteRouterNode("home-01")
	put := func(id string, data []byte, digest string) MutationResult {
		return applyForTest(t, fsm, Mutation{Version: CommandVersion, ID: id, Kind: "RoutePolicy",
			Operations: []Operation{{Op: "put", Path: path, Data: data, ExpectedSHA256: digest}}})
	}
	if result := put("initial", old, ""); !result.OK {
		t.Fatal(result)
	}
	var node map[string]any
	if err := json.Unmarshal(old, &node); err != nil {
		t.Fatal(err)
	}
	node["authorized_routes"] = []string{"192.168.88.0/24", "10.10.0.0/16"}
	updated, _ := json.Marshal(node)
	if result := put("admin", updated, sha256Hex(old)); !result.OK {
		t.Fatal(result)
	}
	if result := put("stale-heartbeat", old, sha256Hex(old)); !result.Conflict {
		t.Fatal("stale heartbeat overwrote Controller grant")
	}
	stored, err := os.ReadFile(filepath.Join(root, path))
	if err != nil || !bytes.Equal(stored, updated) {
		t.Fatalf("grant changed: %s %v", stored, err)
	}
}

func TestWaitRevisionRequiresAppliedStateAndRepairsProjection(t *testing.T) {
	_, fsm, root := testFSM(t)
	node := &Node{fsm: fsm}
	if node.WaitRevision(0, time.Second) == nil {
		t.Fatal("missing mutation revision accepted")
	}
	if node.WaitRevision(1, time.Millisecond) == nil {
		t.Fatal("unapplied revision acknowledged")
	}
	path := "control/nodes/home-01.json"
	result := applyForTest(t, fsm, Mutation{Version: CommandVersion, ID: "project", Kind: "Test",
		Operations: []Operation{{Op: "put", Path: path, Data: siteRouterNode("home-01")}}})
	if !result.OK {
		t.Fatal(result)
	}
	if err := os.Remove(filepath.Join(root, path)); err != nil {
		t.Fatal(err)
	}
	if err := node.WaitRevision(result.Revision, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, path)); err != nil {
		t.Fatal("applied revision returned without repairing its projection", err)
	}
}
