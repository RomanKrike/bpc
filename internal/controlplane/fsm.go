package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

const (
	CommandVersion       = 1
	ControlSchemaVersion = 1
)

var replicatedPrefixes = []string{
	"control/identity/users/",
	"control/identity/usernames/",
	"control/identity/access/",
	"control/identity/refresh/",
	"control/devices/",
	"control/access/",
	"control/node-join/",
	"control/node-join-used/",
	"control/nodes/",
	"control/node-public-keys/",
	"control/node-credentials/",
	"control/routes/",
	"control/revocations/",
	"cluster/controllers/",
}

var replicatedExact = map[string]struct{}{
	"cluster/cluster.json": {},
}

type Operation struct {
	Op             string `json:"op"`
	Path           string `json:"path"`
	Data           []byte `json:"data,omitempty"`
	IfAbsent       bool   `json:"if_absent,omitempty"`
	RequirePresent bool   `json:"require_present,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type Mutation struct {
	Version    int         `json:"version"`
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	IssuedAt   int64       `json:"issued_at"`
	Operations []Operation `json:"operations"`
}

type MutationResult struct {
	OK       bool   `json:"ok"`
	Revision uint64 `json:"revision"`
	Error    string `json:"error,omitempty"`
	Conflict bool   `json:"conflict,omitempty"`
}

type snapshotEnvelope struct {
	Version       int               `json:"version"`
	SchemaVersion uint64            `json:"schema_version"`
	Revision      uint64            `json:"revision"`
	Entries       map[string][]byte `json:"entries"`
	Checksum      string            `json:"checksum"`
}

type StateMachine struct {
	store *Store
	root  string
	mu    sync.Mutex
}

func NewStateMachine(store *Store, stateRoot string) *StateMachine {
	return &StateMachine{store: store, root: filepath.Clean(stateRoot)}
}

func NormalizeReplicatedPath(path string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	clean = strings.TrimPrefix(clean, "./")
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || filepath.IsAbs(path) {
		return "", errors.New("invalid canonical path")
	}
	if _, ok := replicatedExact[clean]; ok {
		return clean, nil
	}
	for _, prefix := range replicatedPrefixes {
		if strings.HasPrefix(clean, prefix) && len(clean) > len(prefix) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("path is not replicated canonical state: %s", clean)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func (f *StateMachine) Apply(log *raft.Log) interface{} {
	var command Mutation
	if err := json.Unmarshal(log.Data, &command); err != nil {
		return MutationResult{Error: "invalid mutation encoding: " + err.Error()}
	}
	if command.Version != CommandVersion || command.ID == "" || command.Kind == "" {
		return MutationResult{Error: "unsupported or incomplete mutation"}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	normalized := make([]Operation, 0, len(command.Operations))
	for _, op := range command.Operations {
		path, err := NormalizeReplicatedPath(op.Path)
		if err != nil {
			return MutationResult{Error: err.Error()}
		}
		op.Path = path
		if op.Op != "put" && op.Op != "delete" {
			return MutationResult{Error: "unsupported operation: " + op.Op}
		}
		normalized = append(normalized, op)
	}

	var revision uint64
	var conflict string
	err := f.store.db.Update(func(tx *bolt.Tx) error {
		canonical := tx.Bucket(bucketCanonical)
		meta := tx.Bucket(bucketMeta)
		for _, op := range normalized {
			existing := canonical.Get([]byte(op.Path))
			if op.IfAbsent && existing != nil {
				conflict = "path already exists: " + op.Path
				return nil
			}
			if op.RequirePresent && existing == nil {
				conflict = "path does not exist: " + op.Path
				return nil
			}
			if op.ExpectedSHA256 != "" {
				if existing == nil || sha256Hex(existing) != strings.ToLower(op.ExpectedSHA256) {
					conflict = "precondition failed: " + op.Path
					return nil
				}
			}
		}
		if conflict != "" {
			revision = decodeU64(meta.Get(keyRevision))
			return nil
		}
		revision = decodeU64(meta.Get(keyRevision)) + 1
		for _, op := range normalized {
			switch op.Op {
			case "put":
				if err := canonical.Put([]byte(op.Path), op.Data); err != nil {
					return err
				}
			case "delete":
				if err := canonical.Delete([]byte(op.Path)); err != nil {
					return err
				}
			}
		}
		if err := meta.Put(keyRevision, u64key(revision)); err != nil {
			return err
		}
		if err := meta.Put(keySchema, u64key(ControlSchemaVersion)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return MutationResult{Error: err.Error()}
	}
	if conflict != "" {
		return MutationResult{Revision: revision, Error: conflict, Conflict: true}
	}
	if err := f.projectOperations(normalized); err != nil {
		return MutationResult{Revision: revision, Error: "state committed but projection failed: " + err.Error()}
	}
	return MutationResult{OK: true, Revision: revision}
}

func (f *StateMachine) projectOperations(ops []Operation) error {
	for _, op := range ops {
		target := filepath.Join(f.root, filepath.FromSlash(op.Path))
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), f.root+string(os.PathSeparator)) {
			return errors.New("projection escaped state root")
		}
		switch op.Op {
		case "put":
			if err := atomicProjectionWrite(target, op.Data); err != nil {
				return err
			}
		case "delete":
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func atomicProjectionWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bpc-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (f *StateMachine) ReconcileProjection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.store.canonicalEntries()
	if err != nil {
		return err
	}
	present := make(map[string]struct{}, len(entries))
	for path, data := range entries {
		present[path] = struct{}{}
		if err := atomicProjectionWrite(filepath.Join(f.root, filepath.FromSlash(path)), data); err != nil {
			return err
		}
	}
	existing, err := ScanReplicatedProjection(f.root)
	if err != nil {
		return err
	}
	for path := range existing {
		if _, ok := present[path]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(f.root, filepath.FromSlash(path))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func ScanReplicatedProjection(root string) (map[string][]byte, error) {
	result := map[string][]byte{}
	candidates := make([]string, 0, len(replicatedPrefixes)+len(replicatedExact))
	candidates = append(candidates, replicatedPrefixes...)
	for path := range replicatedExact {
		candidates = append(candidates, path)
	}
	sort.Strings(candidates)
	for _, relative := range candidates {
		full := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Stat(full)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			data, err := os.ReadFile(full)
			if err != nil {
				return nil, err
			}
			result[relative] = data
			continue
		}
		err = filepath.WalkDir(full, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			normalized, err := NormalizeReplicatedPath(filepath.ToSlash(rel))
			if err != nil {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[normalized] = data
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func BootstrapMutation(root, id string, issuedAt int64) (Mutation, error) {
	entries, err := ScanReplicatedProjection(root)
	if err != nil {
		return Mutation{}, err
	}
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	ops := make([]Operation, 0, len(paths))
	for _, path := range paths {
		ops = append(ops, Operation{Op: "put", Path: path, Data: entries[path], IfAbsent: true})
	}
	return Mutation{Version: CommandVersion, ID: id, Kind: "BootstrapCanonicalState", IssuedAt: issuedAt, Operations: ops}, nil
}

func (f *StateMachine) ExportSnapshot() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.store.canonicalEntries()
	if err != nil {
		return nil, err
	}
	revision, err := f.store.revision()
	if err != nil {
		return nil, err
	}
	schema, err := f.store.schemaVersion()
	if err != nil {
		return nil, err
	}
	envelope := snapshotEnvelope{Version: 1, SchemaVersion: schema, Revision: revision, Entries: entries}
	envelope.Checksum = snapshotChecksum(envelope.SchemaVersion, envelope.Revision, envelope.Entries)
	return json.Marshal(envelope)
}

func (f *StateMachine) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.store.canonicalEntries()
	if err != nil {
		return nil, err
	}
	revision, err := f.store.revision()
	if err != nil {
		return nil, err
	}
	schema, err := f.store.schemaVersion()
	if err != nil {
		return nil, err
	}
	envelope := snapshotEnvelope{Version: 1, SchemaVersion: schema, Revision: revision, Entries: entries}
	envelope.Checksum = snapshotChecksum(envelope.SchemaVersion, envelope.Revision, envelope.Entries)
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return &stateSnapshot{data: raw}, nil
}

type stateSnapshot struct{ data []byte }

func (s *stateSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *stateSnapshot) Release() {}

func (f *StateMachine) Restore(reader io.ReadCloser) error {
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, 128*1024*1024))
	if err != nil {
		return err
	}
	var envelope snapshotEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Version != 1 || envelope.SchemaVersion > ControlSchemaVersion {
		return errors.New("incompatible canonical snapshot schema")
	}
	expected := snapshotChecksum(envelope.SchemaVersion, envelope.Revision, envelope.Entries)
	if expected != envelope.Checksum {
		return errors.New("canonical snapshot checksum mismatch")
	}

	f.mu.Lock()
	err = f.store.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(bucketCanonical); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		canonical, err := tx.CreateBucket(bucketCanonical)
		if err != nil {
			return err
		}
		paths := make([]string, 0, len(envelope.Entries))
		for path := range envelope.Entries {
			if _, err := NormalizeReplicatedPath(path); err != nil {
				return err
			}
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			if err := canonical.Put([]byte(path), envelope.Entries[path]); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bucketMeta)
		if err := meta.Put(keyRevision, u64key(envelope.Revision)); err != nil {
			return err
		}
		return meta.Put(keySchema, u64key(envelope.SchemaVersion))
	})
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.ReconcileProjection()
}

func snapshotChecksum(schema, revision uint64, entries map[string][]byte) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "schema=%d\nrevision=%d\n", schema, revision)
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(sha256Hex(entries[path])))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (f *StateMachine) Revision() uint64 {
	revision, _ := f.store.revision()
	return revision
}

func (f *StateMachine) SchemaVersion() uint64 {
	version, _ := f.store.schemaVersion()
	return version
}
