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
	Voter             bool   `json:"voter"`
	SoftwareVersion   string `json:"software_version,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
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

	material := controlplane.TLSMaterial{CertificateFile: *certFile, KeyFile: *keyFile, CAFile: *caFile}
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
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	status, err := s.node.Status()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "raft_role": status.RaftRole, "leader_id": status.LeaderID})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID, "software_version": s.version, "status": status,
	})
}

func (s *server) mutate(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	if !s.node.IsLeader() {
		s.forward(w, r.Method, r.URL.Path, raw)
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
	if err := json.Unmarshal(raw, &request); err != nil || request.NodeID == "" || request.RaftAddress == "" || request.APIAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "node_id, raft_address and api_address are required"})
		return
	}
	if err := s.node.AddMember(request.NodeID, request.RaftAddress, request.Voter, 15*time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	now := time.Now().Unix()
	state := "nonvoter"
	if request.Voter {
		state = "voter"
	}
	record := controllerRecord{NodeID: request.NodeID, RaftAddress: request.RaftAddress, APIAddress: request.APIAddress, State: state,
		SoftwareVersion: request.SoftwareVersion, ProtocolVersion: 1, StateSchema: controlplane.ControlSchemaVersion,
		CertificateSHA256: request.CertificateSHA256, UpdatedAt: now}
	recordRaw, _ := json.Marshal(record)
	result, err := s.node.Submit(controlplane.Mutation{Version: controlplane.CommandVersion, ID: randomID(), Kind: "AddController", IssuedAt: now,
		Operations: []controlplane.Operation{{Op: "put", Path: "cluster/controllers/" + request.NodeID + ".json", Data: recordRaw}}}, 10*time.Second)
	if err != nil || !result.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": fmt.Sprintf("membership changed but canonical record failed: %v %+v", err, result)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": result.Revision, "state": state})
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
	path := filepath.Join(s.stateRoot, "cluster", "controllers", request.NodeID+".json")
	record := controllerRecord{NodeID: request.NodeID, State: "revoked", UpdatedAt: time.Now().Unix(), ProtocolVersion: 1, StateSchema: controlplane.ControlSchemaVersion}
	if existing, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(existing, &record)
		record.State = "revoked"
		record.UpdatedAt = time.Now().Unix()
	}
	recordRaw, _ := json.Marshal(record)
	result, err := s.node.Submit(controlplane.Mutation{Version: controlplane.CommandVersion, ID: randomID(), Kind: "RevokeController", IssuedAt: record.UpdatedAt,
		Operations: []controlplane.Operation{{Op: "put", Path: "cluster/controllers/" + request.NodeID + ".json", Data: recordRaw}}}, 10*time.Second)
	if err != nil || !result.OK {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": fmt.Sprintf("failed to commit controller revocation: %v %+v", err, result)})
		return
	}
	if err := s.node.RemoveMember(request.NodeID, request.Force, 15*time.Second); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "revocation_committed": true})
		return
	}
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
