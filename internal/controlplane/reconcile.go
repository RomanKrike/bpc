package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

const RevisionRecoveryVersion = 1

func (n *Node) RecoveryGateways() ([]string, error) {
	var ids []string
	err := n.store.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCanonical).ForEach(func(k, v []byte) error {
			if !strings.HasPrefix(string(k), "control/nodes/") {
				return nil
			}
			var record struct {
				NodeID  string          `json:"node_id"`
				Roles   map[string]bool `json:"roles"`
				Revoked bool            `json:"revoked"`
			}
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			if record.Roles["gateway"] && !record.Revoked {
				if record.NodeID == "" || string(k) != "control/nodes/"+record.NodeID+".json" {
					return errors.New("invalid canonical Gateway identity")
				}
				ids = append(ids, record.NodeID)
			}
			return nil
		})
	})
	return ids, err
}

// RecoveryState exposes committed reconstruction metadata, never policy data.
// It intentionally works below the local floor so an admin can reconcile it.
type RecoveryState struct {
	Version            int    `json:"recovery_version"`
	NodeID             string `json:"node_id"`
	Index              uint64 `json:"index"`
	Revision           uint64 `json:"revision"`
	Floor              uint64 `json:"floor"`
	Digest             string `json:"digest"`
	ConfigurationIndex uint64 `json:"configuration_index"`
}

func (n *Node) RecoveryState(index uint64, timeout time.Duration) (RecoveryState, error) {
	if index == 0 {
		if !n.IsLeader() {
			return RecoveryState{}, ErrNotLeader
		}
		if err := n.raft.Barrier(timeout).Error(); err != nil {
			return RecoveryState{}, err
		}
		index = n.raft.CommitIndex()
	} else {
		deadline := time.Now().Add(timeout)
		for n.raft.AppliedIndex() < index {
			if time.Now().After(deadline) {
				return RecoveryState{}, errors.New("recovery catch-up timeout")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	configuration := n.raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		return RecoveryState{}, err
	}
	view := RecoveryState{Version: RevisionRecoveryVersion, NodeID: n.config.NodeID, Index: index, ConfigurationIndex: configuration.Index()}
	n.fsm.mu.Lock()
	defer n.fsm.mu.Unlock()
	err := n.store.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		view.Revision = decodeU64(meta.Get(keyRevision))
		view.Floor = decodeU64(meta.Get(keyRevisionFloor))
		entries := make(map[string][]byte)
		if err := tx.Bucket(bucketCanonical).ForEach(func(k, v []byte) error {
			entries[string(k)] = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return err
		}
		view.Digest = snapshotChecksum(decodeU64(meta.Get(keySchema)), 0, entries)
		return nil
	})
	return view, err
}

// ReconcileRevision commits a policy-free revision advance against an observed
// canonical digest/configuration. The API first verifies every member and receipt.
func (n *Node) ReconcileRevision(view RecoveryState, minimum uint64, timeout time.Duration) (MutationResult, error) {
	n.mutationMu.Lock()
	defer n.mutationMu.Unlock()
	if !n.IsLeader() {
		return MutationResult{}, ErrNotLeader
	}
	current, err := n.RecoveryState(0, timeout)
	if err != nil {
		return MutationResult{}, err
	}
	if view.Digest != current.Digest || view.ConfigurationIndex != current.ConfigurationIndex || view.Revision != current.Revision {
		return MutationResult{}, errors.New("canonical state or membership changed; retry reconciliation")
	}
	if minimum < current.Floor || minimum < current.Revision || minimum == 0 || minimum == ^uint64(0) {
		return MutationResult{}, errors.New("invalid reconciliation minimum")
	}
	command := Mutation{Version: CommandVersion, ID: fmt.Sprintf("revision-recovery-%d", minimum), Kind: "ReconcileRevision", RevisionMinimum: minimum}
	raw, err := json.Marshal(command)
	if err != nil {
		return MutationResult{}, err
	}
	future := n.raft.Apply(raw, timeout)
	if err := future.Error(); err != nil {
		return MutationResult{}, err
	}
	result, ok := future.Response().(MutationResult)
	if !ok || !result.OK {
		return MutationResult{}, fmt.Errorf("reconciliation failed: %v", future.Response())
	}
	result.CommitIndex = future.Index()
	if _, _, err := n.StrongRead(timeout); err != nil {
		return MutationResult{}, err
	}
	return result, nil
}
