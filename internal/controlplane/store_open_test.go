package controlplane

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestOfflineStoreOpenPreservesDatabaseBytes(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		name := "initialized"
		if incomplete {
			name = "missing_bucket"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			store, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if incomplete {
				if err := store.db.Update(func(tx *bolt.Tx) error {
					return tx.DeleteBucket(bucketLogs)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			store, err = openStore(path, false)
			if incomplete {
				if err == nil {
					_ = store.Close()
					t.Fatal("offline open initialized an incomplete database")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("offline open changed database bytes")
			}
			// Also verify that refusal releases the exclusive Bolt lock.
			store, err = OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			_ = store.Close()
		})
	}
}
