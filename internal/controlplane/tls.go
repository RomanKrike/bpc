package controlplane

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

type TLSMaterial struct {
	CertificateFile string
	KeyFile         string
	CAFile          string
	MembershipDir   string
	ClusterID       string
}

type membershipRecord struct {
	NodeID            string `json:"node_id"`
	State             string `json:"state"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func loadTLSMaterial(material TLSMaterial) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.KeyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	rawCA, err := os.ReadFile(material.CAFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rawCA) {
		return tls.Certificate{}, nil, fmt.Errorf("failed to parse cluster CA: %s", material.CAFile)
	}
	return cert, pool, nil
}

func verifyControllerMembership(material TLSMaterial, cert *x509.Certificate) error {
	if strings.TrimSpace(material.MembershipDir) == "" {
		return nil
	}
	if strings.TrimSpace(material.ClusterID) == "" {
		return fmt.Errorf("cluster identity is missing")
	}
	nodeID := strings.TrimSpace(cert.Subject.CommonName)
	if nodeID == "" || nodeID == "." || nodeID == ".." ||
		strings.ContainsAny(nodeID, "/\\") {
		return fmt.Errorf("controller certificate has invalid node identity")
	}

	path := filepath.Join(material.MembershipDir, nodeID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("controller %s is not a cluster member: %w", nodeID, err)
	}
	var record membershipRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("invalid controller membership record for %s: %w", nodeID, err)
	}
	if record.NodeID != nodeID {
		return fmt.Errorf("controller membership identity mismatch")
	}
	switch record.State {
	case "pending", "nonvoter", "voter":
	default:
		return fmt.Errorf("controller %s membership state is %q", nodeID, record.State)
	}

	digest := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(digest[:])
	expected := strings.ToLower(strings.TrimSpace(record.CertificateSHA256))
	if len(expected) != len(fingerprint) ||
		subtle.ConstantTimeCompare([]byte(expected), []byte(fingerprint)) != 1 {
		return fmt.Errorf("controller %s certificate fingerprint mismatch", nodeID)
	}

	expectedURI := "bpc://" + material.ClusterID + "/controller/" + nodeID
	foundURI := false
	for _, uri := range cert.URIs {
		if uri.String() == expectedURI {
			foundURI = true
			break
		}
	}
	if !foundURI {
		return fmt.Errorf("controller %s certificate does not bind cluster identity", nodeID)
	}
	return nil
}

func verifyPeer(material TLSMaterial) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("controller peer certificate is missing")
		}
		return verifyControllerMembership(material, state.PeerCertificates[0])
	}
}

func ServerTLSConfig(material TLSMaterial) (*tls.Config, error) {
	cert, pool, err := loadTLSMaterial(material)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        pool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: verifyPeer(material),
	}, nil
}

func ClientTLSConfig(material TLSMaterial, serverName string) (*tls.Config, error) {
	cert, pool, err := loadTLSMaterial(material)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		ServerName:       serverName,
		VerifyConnection: verifyPeer(material),
	}, nil
}

type advertisedAddr string

func (a advertisedAddr) Network() string { return "tcp" }
func (a advertisedAddr) String() string  { return string(a) }

type TLSStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	server    *tls.Config
	material  TLSMaterial
}

func NewTLSStreamLayer(
	bindAddress string,
	advertiseAddress string,
	material TLSMaterial,
) (*TLSStreamLayer, error) {
	listener, err := net.Listen("tcp", bindAddress)
	if err != nil {
		return nil, err
	}
	server, err := ServerTLSConfig(material)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if advertiseAddress == "" {
		advertiseAddress = listener.Addr().String()
	}
	return &TLSStreamLayer{
		listener: listener, advertise: advertisedAddr(advertiseAddress),
		server: server, material: material,
	}, nil
}

func (l *TLSStreamLayer) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	secured := tls.Server(conn, l.server)
	if err := secured.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secured, nil
}

func (l *TLSStreamLayer) Close() error   { return l.listener.Close() }
func (l *TLSStreamLayer) Addr() net.Addr { return l.advertise }

func (l *TLSStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(string(address))
	if err != nil {
		return nil, err
	}
	config, err := ClientTLSConfig(l.material, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", string(address), config)
}
