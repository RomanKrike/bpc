package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hashicorp/raft"
)

type TLSMaterial struct {
	CertificateFile string
	KeyFile         string
	CAFile          string
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

func ServerTLSConfig(material TLSMaterial) (*tls.Config, error) {
	cert, pool, err := loadTLSMaterial(material)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func ClientTLSConfig(material TLSMaterial, serverName string) (*tls.Config, error) {
	cert, pool, err := loadTLSMaterial(material)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
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

func NewTLSStreamLayer(bindAddress, advertiseAddress string, material TLSMaterial) (*TLSStreamLayer, error) {
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
