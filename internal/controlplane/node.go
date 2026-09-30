package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

const ProtocolVersion = 1

var ErrNotLeader = errors.New("not raft leader")

type NodeConfig struct {
	NodeID            string
	RaftBindAddress   string
	RaftAddress       string
	StateRoot         string
	DataDir           string
	TLS               TLSMaterial
	Bootstrap         bool
	SnapshotRetain    int
	SnapshotThreshold uint64
	SnapshotInterval  time.Duration
}

type ControllerMember struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage string `json:"suffrage"`
}

type Status struct {
	NodeID          string             `json:"node_id"`
	RaftRole        string             `json:"raft_role"`
	LeaderID        string             `json:"leader_id"`
	LeaderAddress   string             `json:"leader_address"`
	Term            uint64             `json:"term"`
	CommitIndex     uint64             `json:"commit_index"`
	LastApplied     uint64             `json:"last_applied"`
	LastLogIndex    uint64             `json:"last_log_index"`
	SnapshotIndex   uint64             `json:"snapshot_index"`
	Revision        uint64             `json:"revision"`
	StateSchema     uint64             `json:"state_schema_version"`
	ProtocolVersion uint64             `json:"protocol_version"`
	RaftProtocol    uint64             `json:"raft_protocol_version"`
	PeerCount       int                `json:"peer_count"`
	ReplicationLag  uint64             `json:"replication_lag"`
	Members         []ControllerMember `json:"members"`
	Voters          int                `json:"voters"`
	Quorum          int                `json:"quorum"`
}

type Node struct {
	config    NodeConfig
	store     *Store
	fsm       *StateMachine
	raft      *raft.Raft
	transport *raft.NetworkTransport
}

func NewNode(config NodeConfig) (*Node, error) {
	if strings.TrimSpace(config.NodeID) == "" || strings.TrimSpace(config.RaftAddress) == "" {
		return nil, errors.New("node id and raft advertise address are required")
	}
	if strings.TrimSpace(config.RaftBindAddress) == "" {
		config.RaftBindAddress = config.RaftAddress
	}
	if config.SnapshotRetain <= 0 {
		config.SnapshotRetain = 3
	}
	if config.SnapshotThreshold == 0 {
		config.SnapshotThreshold = 64
	}
	if config.SnapshotInterval <= 0 {
		config.SnapshotInterval = 30 * time.Second
	}
	if err := os.MkdirAll(config.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(config.DataDir, 0o700); err != nil {
		return nil, err
	}

	store, err := OpenStore(filepath.Join(config.DataDir, "raft-state.db"))
	if err != nil {
		return nil, err
	}
	fsm := NewStateMachine(store, config.StateRoot)

	snapshots, err := raft.NewFileSnapshotStore(config.DataDir, config.SnapshotRetain, os.Stderr)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	stream, err := NewTLSStreamLayer(config.RaftBindAddress, config.RaftAddress, config.TLS)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	transport := raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
		Stream:  stream,
		MaxPool: 4,
		Timeout: 5 * time.Second,
	})

	raftConfig := raft.DefaultConfig()
	raftConfig.LocalID = raft.ServerID(config.NodeID)
	raftConfig.SnapshotThreshold = config.SnapshotThreshold
	raftConfig.SnapshotInterval = config.SnapshotInterval
	raftConfig.ShutdownOnRemove = true

	existing, err := raft.HasExistingState(store, store, snapshots)
	if err != nil {
		_ = transport.Close()
		_ = store.Close()
		return nil, err
	}
	if existing {
		if err := fsm.ReconcileProjection(); err != nil {
			_ = transport.Close()
			_ = store.Close()
			return nil, fmt.Errorf("reconcile canonical state: %w", err)
		}
	}
	// A fresh bootstrap Controller must keep its Stage 4.5 canonical files until
	// BootstrapMutation commits them. A fresh joining Controller must keep its
	// seed cluster trust files until Raft snapshot/log catch-up replaces them.

	instance, err := raft.NewRaft(raftConfig, fsm, store, store, snapshots, transport)
	if err != nil {
		_ = transport.Close()
		_ = store.Close()
		return nil, err
	}
	if !existing && config.Bootstrap {
		future := instance.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{
			ID:       raft.ServerID(config.NodeID),
			Address:  raft.ServerAddress(config.RaftAddress),
			Suffrage: raft.Voter,
		}}})
		if err := future.Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
			_ = instance.Shutdown().Error()
			_ = transport.Close()
			_ = store.Close()
			return nil, err
		}
	}
	return &Node{config: config, store: store, fsm: fsm, raft: instance, transport: transport}, nil
}

func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

func (n *Node) Leader() (string, string) {
	address, id := n.raft.LeaderWithID()
	return string(id), string(address)
}

func (n *Node) WaitForLeader(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, address := n.Leader()
		if address != "" {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("leader election timeout")
}

func (n *Node) Submit(command Mutation, timeout time.Duration) (MutationResult, error) {
	if !n.IsLeader() {
		return MutationResult{}, ErrNotLeader
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return MutationResult{}, err
	}
	future := n.raft.Apply(raw, timeout)
	if err := future.Error(); err != nil {
		return MutationResult{}, err
	}
	switch response := future.Response().(type) {
	case MutationResult:
		return response, nil
	case error:
		return MutationResult{}, response
	case nil:
		return MutationResult{}, errors.New("empty state-machine response")
	default:
		return MutationResult{}, fmt.Errorf("unexpected state-machine response %T", response)
	}
}

func (n *Node) StrongRead(timeout time.Duration) (uint64, uint64, error) {
	if !n.IsLeader() {
		return 0, 0, ErrNotLeader
	}
	if err := n.raft.Barrier(timeout).Error(); err != nil {
		return 0, 0, err
	}
	if err := n.fsm.ReconcileProjection(); err != nil {
		return 0, 0, err
	}
	return n.raft.CommitIndex(), n.fsm.Revision(), nil
}

func (n *Node) WaitApplied(index uint64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.raft.AppliedIndex() >= index {
			return n.fsm.ReconcileProjection()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("local controller did not apply commit index %d before timeout", index)
}

func (n *Node) WaitRevision(revision uint64, timeout time.Duration) error {
	if revision == 0 {
		return errors.New("mutation response has no canonical revision")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.fsm.Revision() >= revision {
			return n.fsm.ReconcileProjection()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("local controller did not project revision %d before timeout", revision)
}

func (n *Node) AddMember(id, address string, voter bool, timeout time.Duration) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	var future raft.IndexFuture
	if voter {
		future = n.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(address), 0, timeout)
	} else {
		future = n.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(address), 0, timeout)
	}
	return future.Error()
}

func (n *Node) RemoveMember(id string, force bool, timeout time.Duration) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	configuration := n.raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		return err
	}
	voters := 0
	found := false
	for _, server := range configuration.Configuration().Servers {
		if server.Suffrage == raft.Voter {
			voters++
		}
		if string(server.ID) == id {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("controller %s is not a raft member", id)
	}
	if voters <= 2 && !force {
		return errors.New("refusing to shrink controller cluster below two voters without force")
	}
	return n.raft.RemoveServer(raft.ServerID(id), 0, timeout).Error()
}

func (n *Node) Snapshot() error { return n.raft.Snapshot().Error() }

func (n *Node) ExportSnapshot() ([]byte, error) { return n.fsm.ExportSnapshot() }

func (n *Node) Revision() uint64 { return n.fsm.Revision() }

func SnapshotClusterID(raw []byte) (string, error) {
	var envelope snapshotEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", err
	}
	if envelope.Version != 1 || envelope.SchemaVersion > ControlSchemaVersion {
		return "", errors.New("incompatible canonical snapshot schema")
	}
	if snapshotChecksum(envelope.SchemaVersion, envelope.Revision, envelope.Entries) != envelope.Checksum {
		return "", errors.New("canonical snapshot checksum mismatch")
	}
	clusterRaw, ok := envelope.Entries["cluster/cluster.json"]
	if !ok {
		return "", errors.New("canonical snapshot does not contain cluster metadata")
	}
	var cluster struct {
		ClusterID string `json:"cluster_id"`
	}
	if err := json.Unmarshal(clusterRaw, &cluster); err != nil {
		return "", err
	}
	cluster.ClusterID = strings.TrimSpace(cluster.ClusterID)
	if cluster.ClusterID == "" {
		return "", errors.New("canonical snapshot cluster_id is missing")
	}
	return cluster.ClusterID, nil
}

func (n *Node) RestoreSnapshot(raw []byte, timeout time.Duration) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	if _, err := SnapshotClusterID(raw); err != nil {
		return err
	}
	configuration := n.raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		return err
	}
	stats := n.raft.Stats()
	meta := &raft.SnapshotMeta{
		Version:            raft.SnapshotVersionMax,
		Index:              n.raft.LastIndex(),
		Term:               parseUint(stats["term"]),
		Configuration:      configuration.Configuration(),
		ConfigurationIndex: configuration.Index(),
		Size:               int64(len(raw)),
	}
	return n.raft.Restore(meta, bytes.NewReader(raw), timeout)
}

func (n *Node) Status() (Status, error) {
	stats := n.raft.Stats()
	status := Status{
		NodeID:          n.config.NodeID,
		RaftRole:        stats["state"],
		Revision:        n.fsm.Revision(),
		StateSchema:     n.fsm.SchemaVersion(),
		ProtocolVersion: ProtocolVersion,
		RaftProtocol:    parseUint(stats["protocol_version"]),
		Term:            parseUint(stats["term"]),
		CommitIndex:     parseUint(stats["commit_index"]),
		LastApplied:     parseUint(stats["applied_index"]),
		LastLogIndex:    parseUint(stats["last_log_index"]),
		SnapshotIndex:   parseUint(stats["last_snapshot_index"]),
	}
	status.LeaderID, status.LeaderAddress = n.Leader()
	future := n.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return status, err
	}
	for _, member := range future.Configuration().Servers {
		item := ControllerMember{ID: string(member.ID), Address: string(member.Address), Suffrage: member.Suffrage.String()}
		status.Members = append(status.Members, item)
		if member.Suffrage == raft.Voter {
			status.Voters++
		}
	}
	if status.Voters > 0 {
		status.Quorum = status.Voters/2 + 1
	}
	if len(status.Members) > 0 {
		status.PeerCount = len(status.Members) - 1
	}
	if status.CommitIndex > status.LastApplied {
		status.ReplicationLag = status.CommitIndex - status.LastApplied
	}
	return status, nil
}

func parseUint(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}

func (n *Node) Shutdown() error {
	raftErr := n.raft.Shutdown().Error()
	transportErr := n.transport.Close()
	storeErr := n.store.Close()
	return errors.Join(raftErr, transportErr, storeErr)
}
