package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RomanKrike/bpc/internal/controlplane"
)

const maxRequestBody = 16 * 1024 * 1024

type controllerRecord struct {
	NodeID            string `json:"node_id"`
	RaftAddress       string `json:"raft_address"`
	APIAddress        string `json:"api_address"`
	PublicURL         string `json:"public_url,omitempty"`
	State             string `json:"state"`
	SoftwareVersion   string `json:"software_version,omitempty"`
	ProtocolVersion   int    `json:"protocol_version"`
	StateSchema       int    `json:"state_schema_version"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	UpdatedAt         int64  `json:"updated_at"`
}

type server struct {
	node      *controlplane.Node
	stateRoot string
	tls       controlplane.TLSMaterial
	version   string
}

type addMemberRequest struct {
	NodeID            string `json:"node_id"`
	RaftAddress       string `json:"raft_address"`
	APIAddress        string `json:"api_address"`
	PublicURL         string `json:"public_url"`
	Voter             bool   `json:"voter"`
	SoftwareVersion   string `json:"software_version,omitempty"`
	ProtocolVersion   int    `json:"protocol_version"`
	StateSchema       int    `json:"state_schema_version"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
}

type restoreRequest struct {
	ClusterID string          `json:"cluster_id"`
	Snapshot  json.RawMessage `json:"snapshot"`
	Force     bool            `json:"force"`
}

type removeMemberRequest struct {
	NodeID string `json:"node_id"`
	Force  bool   `json:"force"`
}

func main() {
	var (
		nodeID      = flag.String("node-id", "", "canonical BPC Node ID")
		raftBind    = flag.String("raft-bind-address", "", "Controller Raft listen address")
		raftAddress = flag.String("raft-address", "", "Controller Raft advertised address")
		clusterAPI  = flag.String("cluster-api-address", "", "mTLS Controller API listen address")
		localAPI    = flag.String("local-api-address", "127.0.0.1:9446", "loopback control API")
		stateRoot   = flag.String("state-root", "/etc/bpc-connect", "BPC canonical state root")
		dataDir     = flag.String("data-dir", "/etc/bpc-connect/cluster/raft", "persistent Raft directory")
		certFile    = flag.String("cert-file", "", "Controller certificate")
		keyFile     = flag.String("key-file", "", "Controller private key")
		caFile      = flag.String("ca-file", "", "BPC cluster CA")
		bootstrap   = flag.Bool("bootstrap", false, "bootstrap the first Controller")
		version     = flag.String("software-version", "source", "BPC software version")
		localToken  = flag.String("local-api-token-file", "", "root-only local API bearer token file")
	)
	flag.Parse()
	for name, value := range map[string]string{
		"node-id": *nodeID, "raft-address": *raftAddress, "cluster-api-address": *clusterAPI,
		"cert-file": *certFile, "key-file": *keyFile, "ca-file": *caFile,
		"local-api-token-file": *localToken,
	} {
		if strings.TrimSpace(value) == "" {
			log.Fatalf("--%s is required", name)
		}
	}
	if host, _, err := net.SplitHostPort(*localAPI); err != nil || (host != "127.0.0.1" && host != "::1" && host != "localhost") {
		log.Fatal("local API must bind loopback only")
	}

	clusterID, err := readClusterID(*stateRoot)
	if err != nil {
		log.Fatal(err)
	}
	material := controlplane.TLSMaterial{
		CertificateFile: *certFile,
		KeyFile:         *keyFile,
		CAFile:          *caFile,
		MembershipDir:   filepath.Join(*stateRoot, "cluster", "controllers"),
		ClusterID:       clusterID,
	}
	node, err := controlplane.NewNode(controlplane.NodeConfig{
		NodeID: *nodeID, RaftBindAddress: *raftBind, RaftAddress: *raftAddress,
		StateRoot: *stateRoot, DataDir: *dataDir,
		TLS: material, Bootstrap: *bootstrap,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer node.Shutdown() //nolint:errcheck

	service := &server{node: node, stateRoot: filepath.Clean(*stateRoot), tls: material, version: *version}
	mux := http.NewServeMux()
	service.routes(mux)
	localSecret, err := readLocalToken(*localToken)
	if err != nil {
		log.Fatal(err)
	}

	localServer := &http.Server{
		Addr: *localAPI, Handler: localAuth(mux, localSecret), ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("local API failed: %v", err)
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}
	}()

	clusterTLS, err := controlplane.ServerTLSConfig(material)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *clusterAPI)
	if err != nil {
		log.Fatal(err)
	}
	clusterServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: clusterTLS}
	go func() {
		secured := tls.NewListener(listener, clusterTLS)
		if err := clusterServer.Serve(secured); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("cluster API failed: %v", err)
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}
	}()

	if *bootstrap {
		if err := node.WaitForLeader(15 * time.Second); err != nil {
			log.Fatal(err)
		}
		if node.Revision() == 0 {
			command, err := controlplane.BootstrapMutation(*stateRoot, randomID(), time.Now().Unix())
			if err != nil {
				log.Fatal(err)
			}
			result, err := node.Submit(command, 10*time.Second)
			if err != nil || !result.OK {
				log.Fatalf("canonical bootstrap failed: result=%+v err=%v", result, err)
			}
			if err := node.Snapshot(); err != nil {
				log.Printf("initial snapshot warning: %v", err)
			}
		}
	}

	log.Printf(
		"bpc-controld node=%s raft_bind=%s raft=%s cluster_api=%s local_api=%s",
		*nodeID, *raftBind, *raftAddress, *clusterAPI, *localAPI,
	)
	select {}
}

func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/mutate", s.mutate)
	mux.HandleFunc("POST /v1/barrier", s.barrier)
	mux.HandleFunc("POST /v1/members/add", s.addMember)
	mux.HandleFunc("POST /v1/members/remove", s.removeMember)
	mux.HandleFunc("POST /v1/snapshot", s.snapshot)
	mux.HandleFunc("GET /v1/export", s.export)
	mux.HandleFunc("POST /v1/restore", s.restore)
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"node_id":              status.NodeID,
		"raft_role":            status.RaftRole,
		"leader_id":            status.LeaderID,
		"commit_index":         status.CommitIndex,
		"last_applied":         status.LastApplied,
		"revision":             status.Revision,
		"software_version":     s.version,
		"protocol_version":     controlplane.ProtocolVersion,
		"state_schema_version": controlplane.ControlSchemaVersion,
	})
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	clusterID := ""
	if raw, err := os.ReadFile(filepath.Join(s.stateRoot, "cluster", "cluster.json")); err == nil {
		var cluster map[string]any
		if json.Unmarshal(raw, &cluster) == nil {
			clusterID, _ = cluster["cluster_id"].(string)
		}
	}
	health := s.controllerHealth(status)
	healthy := 0
	for _, peer := range health {
		if ok, _ := peer["healthy"].(bool); ok {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id":               clusterID,
		"software_version":         s.version,
		"status":                   status,
		"healthy_controller_count": healthy,
		"controller_health":        health,
	})
}

func (s *server) mutate(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	if !s.node.IsLeader() {
		response, status, err := s.forwardBytes(r.Method, r.URL.Path, raw)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		if status == http.StatusOK {
			var result controlplane.MutationResult
			if err := json.Unmarshal(response, &result); err != nil || !result.OK {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid leader mutation response"})
				return
			}
			// Callers read local projected files immediately after a mutation.
			// Leader acknowledgement alone does not provide read-your-writes here.
			if err := s.node.WaitRevision(result.Revision, 10*time.Second); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(response)
		return
	}
	var command controlplane.Mutation
	if err := json.Unmarshal(raw, &command); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid mutation"})
		return
	}
	result, err := s.node.Submit(command, 10*time.Second)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if result.Conflict {
		writeJSON(w, http.StatusConflict, result)
		return
	}
	if !result.OK {
		writeJSON(w, http.StatusInternalServerError, result)
		return
	}
	log.Printf("cluster event=state_mutation kind=%s revision=%d", command.Kind, result.Revision)
	writeJSON(w, http.StatusOK, result)
}

func (s *server) barrier(w http.ResponseWriter, r *http.Request) {
	if !s.node.IsLeader() {
		leaderResponse, status, err := s.forwardBytes(r.Method, r.URL.Path, nil)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write(leaderResponse)
			return
		}
		var value struct {
			CommitIndex uint64 `json:"commit_index"`
			Revision    uint64 `json:"revision"`
		}
		if err := json.Unmarshal(leaderResponse, &value); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid leader barrier response"})
			return
		}
		if err := s.node.WaitApplied(value.CommitIndex, 10*time.Second); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, value)
		return
	}
	index, revision, err := s.node.StrongRead(10 * time.Second)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commit_index": index, "revision": revision})
}

func (s *server) addMember(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	if !s.node.IsLeader() {
		s.forward(w, r.Method, r.URL.Path, raw)
		return
	}
	var request addMemberRequest
	if err := json.Unmarshal(raw, &request); err != nil ||
		request.NodeID == "" || request.RaftAddress == "" || request.APIAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "node_id, raft_address and api_address are required",
		})
		return
	}
	if request.ProtocolVersion != controlplane.ProtocolVersion ||
		request.StateSchema != controlplane.ControlSchemaVersion {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                         "Controller protocol/state schema is incompatible",
			"required_protocol_version":     controlplane.ProtocolVersion,
			"required_state_schema_version": controlplane.ControlSchemaVersion,
		})
		return
	}
	request.PublicURL = strings.TrimRight(strings.TrimSpace(request.PublicURL), "/")
	if !strings.HasPrefix(request.PublicURL, "https://") {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "public_url must use https://",
		})
		return
	}
	fingerprint := strings.ToLower(strings.TrimSpace(request.CertificateSHA256))
	if len(fingerprint) != 64 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "certificate_sha256 is required",
		})
		return
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "certificate_sha256 is invalid",
		})
		return
	}

	now := time.Now().Unix()
	record := controllerRecord{
		NodeID:            request.NodeID,
		RaftAddress:       request.RaftAddress,
		APIAddress:        request.APIAddress,
		PublicURL:         request.PublicURL,
		State:             "pending",
		SoftwareVersion:   request.SoftwareVersion,
		ProtocolVersion:   request.ProtocolVersion,
		StateSchema:       request.StateSchema,
		CertificateSHA256: fingerprint,
		UpdatedAt:         now,
	}
	recordRaw, _ := json.Marshal(record)
	pending, err := s.node.Submit(controlplane.Mutation{
		Version:  controlplane.CommandVersion,
		ID:       randomID(),
		Kind:     "PrepareController",
		IssuedAt: now,
		Operations: []controlplane.Operation{{
			Op:   "put",
			Path: "cluster/controllers/" + request.NodeID + ".json",
			Data: recordRaw,
		}},
	}, 10*time.Second)
	if err != nil || !pending.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": fmt.Sprintf(
				"failed to prepare controller membership: %v %+v",
				err,
				pending,
			),
		})
		return
	}

	if err := s.node.AddMember(
		request.NodeID,
		request.RaftAddress,
		false,
		15*time.Second,
	); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":            err.Error(),
			"pending_revision": pending.Revision,
		})
		return
	}

	record.State = "nonvoter"
	record.UpdatedAt = time.Now().Unix()
	recordRaw, _ = json.Marshal(record)
	nonvoter, err := s.node.Submit(controlplane.Mutation{
		Version:  controlplane.CommandVersion,
		ID:       randomID(),
		Kind:     "ActivateControllerNonvoter",
		IssuedAt: record.UpdatedAt,
		Operations: []controlplane.Operation{{
			Op:   "put",
			Path: "cluster/controllers/" + request.NodeID + ".json",
			Data: recordRaw,
		}},
	}, 10*time.Second)
	if err != nil || !nonvoter.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": fmt.Sprintf(
				"Controller joined as nonvoter but canonical activation failed: %v %+v",
				err,
				nonvoter,
			),
			"pending_revision": pending.Revision,
		})
		return
	}

	if !request.Voter {
		log.Printf(
			"cluster event=membership action=add node_id=%s state=nonvoter",
			request.NodeID,
		)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"revision": nonvoter.Revision,
			"state":    "nonvoter",
		})
		return
	}

	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":             err.Error(),
			"nonvoter_revision": nonvoter.Revision,
		})
		return
	}
	if err := s.waitControllerApplied(record, status.CommitIndex, 30*time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":             err.Error(),
			"state":             "nonvoter",
			"nonvoter_revision": nonvoter.Revision,
		})
		return
	}
	if err := s.node.AddMember(
		request.NodeID,
		request.RaftAddress,
		true,
		15*time.Second,
	); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":             err.Error(),
			"state":             "nonvoter",
			"nonvoter_revision": nonvoter.Revision,
		})
		return
	}

	record.State = "voter"
	record.UpdatedAt = time.Now().Unix()
	recordRaw, _ = json.Marshal(record)
	result, err := s.node.Submit(controlplane.Mutation{
		Version:  controlplane.CommandVersion,
		ID:       randomID(),
		Kind:     "PromoteControllerVoter",
		IssuedAt: record.UpdatedAt,
		Operations: []controlplane.Operation{{
			Op:   "put",
			Path: "cluster/controllers/" + request.NodeID + ".json",
			Data: recordRaw,
		}},
	}, 10*time.Second)
	if err != nil || !result.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": fmt.Sprintf(
				"Controller became a Raft voter but canonical activation failed: %v %+v",
				err,
				result,
			),
			"nonvoter_revision": nonvoter.Revision,
		})
		return
	}
	log.Printf(
		"cluster event=membership action=promote node_id=%s state=voter",
		request.NodeID,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"revision": result.Revision,
		"state":    "voter",
	})
}

func (s *server) waitControllerApplied(
	record controllerRecord,
	target uint64,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	var lastApplied uint64
	var lastErr error
	for time.Now().Before(deadline) {
		health, err := s.probeController(record)
		if err == nil {
			if value, ok := health["last_applied"].(float64); ok && value >= 0 {
				lastApplied = uint64(value)
			}
			if lastApplied >= target {
				return nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf(
			"Controller did not catch up before voter promotion: last_applied=%d target=%d: %w",
			lastApplied,
			target,
			lastErr,
		)
	}
	return fmt.Errorf(
		"Controller did not catch up before voter promotion: last_applied=%d target=%d",
		lastApplied,
		target,
	)
}

func (s *server) removeMember(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	if !s.node.IsLeader() {
		s.forward(w, r.Method, r.URL.Path, raw)
		return
	}
	var request removeMemberRequest
	if err := json.Unmarshal(raw, &request); err != nil || request.NodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "node_id is required"})
		return
	}
	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if request.NodeID == status.NodeID {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "remove the current Leader through another Controller",
		})
		return
	}

	path := filepath.Join(s.stateRoot, "cluster", "controllers", request.NodeID+".json")
	record := controllerRecord{
		NodeID: request.NodeID, State: "revoked", UpdatedAt: time.Now().Unix(),
		ProtocolVersion: controlplane.ProtocolVersion,
		StateSchema:     controlplane.ControlSchemaVersion,
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		_ = json.Unmarshal(existing, &record)
	}
	if err := s.node.RemoveMember(request.NodeID, request.Force, 15*time.Second); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}

	record.State = "revoked"
	record.UpdatedAt = time.Now().Unix()
	recordRaw, _ := json.Marshal(record)
	revocationRaw, _ := json.Marshal(map[string]any{
		"version":    1,
		"kind":       "controller",
		"subject_id": request.NodeID,
		"revoked_at": record.UpdatedAt,
		"reason":     "controller_removed",
	})
	result, err := s.node.Submit(controlplane.Mutation{
		Version:  controlplane.CommandVersion,
		ID:       randomID(),
		Kind:     "RevokeController",
		IssuedAt: record.UpdatedAt,
		Operations: []controlplane.Operation{
			{Op: "put", Path: "cluster/controllers/" + request.NodeID + ".json", Data: recordRaw},
			{Op: "put", Path: "control/revocations/controller-" + request.NodeID + ".json", Data: revocationRaw},
		},
	}, 10*time.Second)
	if err != nil || !result.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": fmt.Sprintf("Controller left Raft but revocation commit failed: %v %+v", err, result),
		})
		return
	}
	log.Printf("cluster event=membership action=remove node_id=%s", request.NodeID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": result.Revision})
}

func (s *server) snapshot(w http.ResponseWriter, r *http.Request) {
	if !s.node.IsLeader() {
		s.forward(w, r.Method, r.URL.Path, nil)
		return
	}
	if err := s.node.Snapshot(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("cluster event=snapshot action=create revision=%d", s.node.Revision())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) export(w http.ResponseWriter, r *http.Request) {
	if !s.node.IsLeader() {
		s.forward(w, r.Method, r.URL.Path, nil)
		return
	}
	if _, _, err := s.node.StrongRead(10 * time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	raw, err := s.node.ExportSnapshot()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(raw)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *server) restore(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "restore is local-only"})
		return
	}
	if !s.node.IsLeader() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "restore must run on the Raft Leader"})
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var request restoreRequest
	if err := json.Unmarshal(raw, &request); err != nil || len(request.Snapshot) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cluster_id and snapshot are required"})
		return
	}
	snapshotCluster, err := controlplane.SnapshotClusterID(request.Snapshot)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	currentCluster, err := readClusterID(s.stateRoot)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if request.ClusterID != currentCluster || snapshotCluster != currentCluster {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "backup cluster identity mismatch"})
		return
	}
	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if status.Voters > 1 && !request.Force {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "restore on a multi-Controller cluster requires force after explicit operator confirmation",
		})
		return
	}
	log.Printf("cluster event=snapshot action=restore cluster_id=%s", currentCluster)
	if err := s.node.RestoreSnapshot(request.Snapshot, 60*time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": s.node.Revision()})
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *server) controllerHealth(status controlplane.Status) map[string]map[string]any {
	result := make(map[string]map[string]any, len(status.Members))
	for _, member := range status.Members {
		if member.ID == status.NodeID {
			result[member.ID] = map[string]any{
				"healthy":      true,
				"raft_role":    status.RaftRole,
				"commit_index": status.CommitIndex,
				"last_applied": status.LastApplied,
			}
			continue
		}
		recordRaw, err := os.ReadFile(
			filepath.Join(s.stateRoot, "cluster", "controllers", member.ID+".json"),
		)
		if err != nil {
			result[member.ID] = map[string]any{"healthy": false, "error": "membership record unavailable"}
			continue
		}
		var record controllerRecord
		if err := json.Unmarshal(recordRaw, &record); err != nil || record.State == "revoked" {
			result[member.ID] = map[string]any{"healthy": false, "error": "membership record invalid"}
			continue
		}
		health, err := s.probeController(record)
		if err != nil {
			result[member.ID] = map[string]any{"healthy": false, "error": err.Error()}
			continue
		}
		health["healthy"] = true
		result[member.ID] = health
	}
	return result
}

func (s *server) probeController(record controllerRecord) (map[string]any, error) {
	host, _, err := net.SplitHostPort(record.APIAddress)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := controlplane.ClientTLSConfig(s.tls, host)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	response, err := client.Get("https://" + record.APIAddress + "/v1/health")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health returned HTTP %d", response.StatusCode)
	}
	var health map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&health); err != nil {
		return nil, err
	}
	return health, nil
}

func (s *server) leaderAPI() (string, error) {
	leaderID, _ := s.node.Leader()
	if leaderID == "" {
		return "", errors.New("raft leader is unknown")
	}
	raw, err := os.ReadFile(filepath.Join(s.stateRoot, "cluster", "controllers", leaderID+".json"))
	if err != nil {
		return "", fmt.Errorf("leader controller record unavailable: %w", err)
	}
	var record controllerRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return "", err
	}
	if record.State == "revoked" || record.APIAddress == "" {
		return "", errors.New("leader controller record is not usable")
	}
	return record.APIAddress, nil
}

func (s *server) forward(w http.ResponseWriter, method, path string, body []byte) {
	raw, status, err := s.forwardBytes(method, path, body)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func (s *server) forwardBytes(method, path string, body []byte) ([]byte, int, error) {
	address, err := s.leaderAPI()
	if err != nil {
		return nil, 0, err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, err
	}
	tlsConfig, err := controlplane.ClientTLSConfig(s.tls, host)
	if err != nil {
		return nil, 0, err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	request, err := http.NewRequest(method, "https://"+address+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBody))
	if err != nil {
		return nil, 0, err
	}
	return raw, response.StatusCode, nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return nil, false
	}
	return raw, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "json encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func randomID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw[:])
}

func readClusterID(stateRoot string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(stateRoot, "cluster", "cluster.json"))
	if err != nil {
		return "", err
	}
	var value struct {
		ClusterID string `json:"cluster_id"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	value.ClusterID = strings.TrimSpace(value.ClusterID)
	if value.ClusterID == "" {
		return "", errors.New("cluster_id is missing")
	}
	return value.ClusterID, nil
}

func readLocalToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if len(token) != 64 {
		return "", errors.New("local API token must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return "", errors.New("local API token is not hexadecimal")
	}
	return token, nil
}

func localAuth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if len(presented) != len(token) ||
			subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "local authentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
