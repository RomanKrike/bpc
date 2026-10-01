package controlplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketLogs       = []byte("raft_logs")
	bucketStable     = []byte("raft_stable")
	bucketCanonical  = []byte("canonical")
	bucketMeta       = []byte("canonical_meta")
	keyRevision      = []byte("revision")
	keySchema        = []byte("schema_version")
	keyAppliedIndex  = []byte("applied_index")
	keyRevisionFloor = []byte("revision_floor")
)

var ErrLegacyReplayUnsafe = errors.New("legacy canonical state has no applied index and no Raft snapshot; automatic replay is unsafe; preserve the DB and use a verified migration checkpoint")

// prepareReplay records a local revision floor before Raft can restore an older
// snapshot. It does not infer committed indexes from revisions or stored logs.
// A legacy materialized DB needs an actual snapshot base for reconstruction.
func (s *Store) prepareReplay(hasSnapshots bool) (uint64, error) {
	var floor uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		for _, key := range [][]byte{keyRevision, keyAppliedIndex, keyRevisionFloor} {
			if raw := meta.Get(key); raw != nil && len(raw) != 8 {
				return fmt.Errorf("invalid canonical metadata %q", key)
			}
		}
		revision := decodeU64(meta.Get(keyRevision))
		first, _ := tx.Bucket(bucketCanonical).Cursor().First()
		if decodeU64(meta.Get(keyAppliedIndex)) == 0 && (revision != 0 || first != nil) && !hasSnapshots {
			return ErrLegacyReplayUnsafe
		}
		floor = decodeU64(meta.Get(keyRevisionFloor))
		if revision > floor {
			floor = revision
		}
		return meta.Put(keyRevisionFloor, u64key(floor))
	})
	return floor, err
}

type Store struct {
	db *bolt.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketLogs, bucketStable, bucketCanonical, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func u64key(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func decodeU64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (s *Store) FirstIndex() (uint64, error) {
	var index uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(bucketLogs).Cursor().First()
		if k != nil {
			index = decodeU64(k)
		}
		return nil
	})
	return index, err
}

func (s *Store) LastIndex() (uint64, error) {
	var index uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(bucketLogs).Cursor().Last()
		if k != nil {
			index = decodeU64(k)
		}
		return nil
	})
	return index, err
}

func (s *Store) GetLog(index uint64, out *raft.Log) error {
	return s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketLogs).Get(u64key(index))
		if raw == nil {
			return raft.ErrLogNotFound
		}
		return decodeRaftLog(raw, out)
	})
}

func (s *Store) StoreLog(log *raft.Log) error { return s.StoreLogs([]*raft.Log{log}) }

func (s *Store) StoreLogs(logs []*raft.Log) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLogs)
		for _, log := range logs {
			raw, err := encodeRaftLog(log)
			if err != nil {
				return err
			}
			if err := b.Put(u64key(log.Index), raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) DeleteRange(min, max uint64) error {
	if max < min {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLogs)
		c := b.Cursor()
		for k, _ := c.Seek(u64key(min)); k != nil; k, _ = c.Next() {
			idx := decodeU64(k)
			if idx > max {
				break
			}
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) Set(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketStable).Put(key, value)
	})
}

func (s *Store) Get(key []byte) ([]byte, error) {
	var result []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketStable).Get(key)
		if value != nil {
			result = append([]byte(nil), value...)
		}
		return nil
	})
	return result, err
}

func (s *Store) SetUint64(key []byte, value uint64) error { return s.Set(key, u64key(value)) }

func (s *Store) GetUint64(key []byte) (uint64, error) {
	value, err := s.Get(key)
	if err != nil {
		return 0, err
	}
	if len(value) == 0 {
		return 0, nil
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("stable uint64 %q has invalid length %d", string(key), len(value))
	}
	return decodeU64(value), nil
}

func encodeRaftLog(log *raft.Log) ([]byte, error) {
	dataLen := len(log.Data)
	extLen := len(log.Extensions)
	raw := make([]byte, 1+8+8+1+8+8+8+dataLen+extLen)
	raw[0] = 1
	off := 1
	binary.BigEndian.PutUint64(raw[off:off+8], log.Index)
	off += 8
	binary.BigEndian.PutUint64(raw[off:off+8], log.Term)
	off += 8
	raw[off] = byte(log.Type)
	off++
	binary.BigEndian.PutUint64(raw[off:off+8], uint64(log.AppendedAt.UnixNano()))
	off += 8
	binary.BigEndian.PutUint64(raw[off:off+8], uint64(dataLen))
	off += 8
	binary.BigEndian.PutUint64(raw[off:off+8], uint64(extLen))
	off += 8
	copy(raw[off:off+dataLen], log.Data)
	off += dataLen
	copy(raw[off:], log.Extensions)
	return raw, nil
}

func decodeRaftLog(raw []byte, out *raft.Log) error {
	const header = 1 + 8 + 8 + 1 + 8 + 8 + 8
	if len(raw) < header || raw[0] != 1 {
		return errors.New("invalid persisted raft log")
	}
	off := 1
	out.Index = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	out.Term = binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	out.Type = raft.LogType(raw[off])
	off++
	ns := int64(binary.BigEndian.Uint64(raw[off : off+8]))
	off += 8
	if ns != 0 {
		out.AppendedAt = time.Unix(0, ns)
	}
	dataLen := binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	extLen := binary.BigEndian.Uint64(raw[off : off+8])
	off += 8
	if dataLen > uint64(len(raw)-off) {
		return errors.New("invalid raft log data length")
	}
	out.Data = append(out.Data[:0], raw[off:off+int(dataLen)]...)
	off += int(dataLen)
	if extLen > uint64(len(raw)-off) {
		return errors.New("invalid raft log extension length")
	}
	out.Extensions = append(out.Extensions[:0], raw[off:off+int(extLen)]...)
	return nil
}

func (s *Store) canonicalGet(path string) ([]byte, bool, error) {
	var value []byte
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketCanonical).Get([]byte(path))
		if raw == nil {
			return nil
		}
		ok = true
		value = append([]byte(nil), raw...)
		return nil
	})
	return value, ok, err
}

func (s *Store) canonicalEntries() (map[string][]byte, error) {
	result := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCanonical).ForEach(func(k, v []byte) error {
			if v != nil {
				result[string(k)] = append([]byte(nil), v...)
			}
			return nil
		})
	})
	return result, err
}

func (s *Store) revision() (uint64, error) {
	var revision uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		revision = decodeU64(tx.Bucket(bucketMeta).Get(keyRevision))
		return nil
	})
	return revision, err
}

func (s *Store) revisionFloor() (uint64, error) {
	var floor uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		floor = decodeU64(tx.Bucket(bucketMeta).Get(keyRevisionFloor))
		return nil
	})
	return floor, err
}

func (s *Store) schemaVersion() (uint64, error) {
	var version uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		version = decodeU64(tx.Bucket(bucketMeta).Get(keySchema))
		return nil
	})
	return version, err
}
