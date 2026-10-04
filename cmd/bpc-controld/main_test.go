package main

import (
	"testing"

	"github.com/RomanKrike/bpc/internal/controlplane"
)

func TestControllerHealthDoesNotCountUnreconciledRevisionAsHealthy(t *testing.T) {
	s := &server{stateRoot: t.TempDir()}
	status := controlplane.Status{NodeID: "self", Revision: 2, RevisionFloor: 50, Members: []controlplane.ControllerMember{{ID: "self"}}}
	if health := s.controllerHealth(status); health["self"]["healthy"] != false {
		t.Fatalf("migration-blocked controller marked healthy: %+v", health)
	}
	status.Revision = 50
	if health := s.controllerHealth(status); health["self"]["healthy"] != true {
		t.Fatalf("reconciled controller marked unhealthy: %+v", health)
	}
}
