package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"crypto/x509"
	"crypto/x509/pkix"
)

func testMembershipCertificate(t *testing.T, clusterID, nodeID string) *x509.Certificate {
	t.Helper()
	uri, err := url.Parse("bpc://" + clusterID + "/controller/" + nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		Raw:     []byte("controller-certificate-" + nodeID),
		Subject: pkix.Name{CommonName: nodeID},
		URIs:    []*url.URL{uri},
	}
}

func writeMembershipRecord(
	t *testing.T,
	dir string,
	nodeID string,
	state string,
	cert *x509.Certificate,
) {
	t.Helper()
	digest := sha256.Sum256(cert.Raw)
	record := membershipRecord{
		NodeID:            nodeID,
		State:             state,
		CertificateSHA256: hex.EncodeToString(digest[:]),
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyControllerMembership(t *testing.T) {
	dir := t.TempDir()
	material := TLSMaterial{MembershipDir: dir, ClusterID: "cluster-a"}
	cert := testMembershipCertificate(t, material.ClusterID, "node-a")
	writeMembershipRecord(t, dir, "node-a", "voter", cert)

	if err := verifyControllerMembership(material, cert); err != nil {
		t.Fatalf("valid controller rejected: %v", err)
	}
}

func TestVerifyControllerMembershipRejectsRevokedOrWrongCertificate(t *testing.T) {
	dir := t.TempDir()
	material := TLSMaterial{MembershipDir: dir, ClusterID: "cluster-a"}
	cert := testMembershipCertificate(t, material.ClusterID, "node-a")
	writeMembershipRecord(t, dir, "node-a", "revoked", cert)

	if err := verifyControllerMembership(material, cert); err == nil {
		t.Fatal("revoked controller was accepted")
	}

	writeMembershipRecord(t, dir, "node-a", "voter", cert)
	wrong := testMembershipCertificate(t, material.ClusterID, "node-a")
	wrong.Raw = []byte("different-certificate")
	if err := verifyControllerMembership(material, wrong); err == nil {
		t.Fatal("certificate fingerprint mismatch was accepted")
	}
}

func TestVerifyControllerMembershipRejectsDifferentCluster(t *testing.T) {
	dir := t.TempDir()
	material := TLSMaterial{MembershipDir: dir, ClusterID: "cluster-a"}
	cert := testMembershipCertificate(t, "cluster-b", "node-a")
	writeMembershipRecord(t, dir, "node-a", "voter", cert)

	if err := verifyControllerMembership(material, cert); err == nil {
		t.Fatal("controller certificate for another cluster was accepted")
	}
}
