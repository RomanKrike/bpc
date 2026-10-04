package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RomanKrike/bpc/internal/controlplane"
)

func TestOneShotControllerRequestsCloseConnections(t *testing.T) {
	for _, mode := range []string{"probe", "forward"} {
		for _, response := range []string{`{"ok":true}`, `invalid-json`} {
			t.Run(mode+"/"+response, func(t *testing.T) {
				closed := make(chan struct{}, 20)
				peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(response))
				}))
				peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed <- struct{}{}
					}
				}
				peer.StartTLS()
				defer peer.Close()
				root := t.TempDir()
				certificate := peer.TLS.Certificates[0]
				key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				certFile, keyFile := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
				if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
					t.Fatal(err)
				}
				material := controlplane.TLSMaterial{CertificateFile: certFile, KeyFile: keyFile, CAFile: certFile}
				s := &server{stateRoot: root, tls: material}
				address := peer.Listener.Addr().String()
				if mode == "forward" {
					node, err := controlplane.NewNode(controlplane.NodeConfig{NodeID: "self", RaftAddress: "127.0.0.1:0", StateRoot: root, DataDir: filepath.Join(root, "raft"), TLS: material, Bootstrap: true})
					if err != nil {
						t.Fatal(err)
					}
					defer node.Shutdown()
					if err := node.WaitForLeader(5 * time.Second); err != nil {
						t.Fatal(err)
					}
					s.node = node
					if err := os.MkdirAll(filepath.Join(root, "cluster/controllers"), 0o700); err != nil {
						t.Fatal(err)
					}
					raw, _ := json.Marshal(controllerRecord{NodeID: "self", APIAddress: address})
					if err := os.WriteFile(filepath.Join(root, "cluster/controllers/self.json"), raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				for i := 0; i < 5; i++ {
					if mode == "probe" {
						_, err := s.probeController(controllerRecord{APIAddress: address})
						if (err == nil) != (response != "invalid-json") {
							t.Fatalf("unexpected probe result: %v", err)
						}
					} else {
						raw, status, err := s.forwardBytes("GET", "/v1/health", nil)
						if err != nil || status != 200 || string(raw) != response {
							t.Fatalf("forward failed: %s %d %v", raw, status, err)
						}
					}
					select {
					case <-closed:
					case <-time.After(time.Second):
						t.Fatal("one-shot request left its connection open")
					}
				}
			})
		}
	}
}
