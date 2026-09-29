package wgshim

import (
	"testing"
	"time"
)

func TestPathHealthMeasuresTransportQuality(t *testing.T) {
	m := NewPathManager([]string{"ru-01"}, PathPolicy{})
	now := time.Unix(100, 0)
	m.Observe(0, 3, []time.Duration{80 * time.Millisecond, 100 * time.Millisecond}, now)
	h := m.Snapshot()[0]
	if !h.Reachable || h.LossPercent < 33 || h.LossPercent > 34 || h.JitterMS == 0 || h.FailureCount != 1 || !h.LastSuccess.Equal(now) {
		t.Fatalf("bad telemetry: %+v", h)
	}
	m.Observe(0, 3, nil, now.Add(time.Second))
	if !m.Snapshot()[0].Reachable {
		t.Fatal("one failed round should not flap")
	}
	m.Observe(0, 3, nil, now.Add(2*time.Second))
	h = m.Snapshot()[0]
	if h.Reachable || h.FailureCount != 7 || !h.LastSuccess.Equal(now) {
		t.Fatalf("failure lost: %+v", h)
	}
}

func TestPathSelectorHysteresisAndStableDuration(t *testing.T) {
	m := NewPathManager([]string{"ru-01", "ru-02"}, PathPolicy{})
	now := time.Unix(100, 0)
	m.Observe(0, 1, []time.Duration{80 * time.Millisecond}, now)
	m.Observe(1, 1, []time.Duration{78 * time.Millisecond}, now)
	if _, changed := m.Select(now); changed {
		t.Fatal("2ms improvement caused switch")
	}
	for i := 0; i < 20; i++ {
		m.Observe(1, 1, []time.Duration{20 * time.Millisecond}, now)
	}
	if _, changed := m.Select(now); changed {
		t.Fatal("switched without stability")
	}
	if _, changed := m.Select(now.Add(4 * time.Second)); changed {
		t.Fatal("stability too short")
	}
	if active, changed := m.Select(now.Add(5 * time.Second)); !changed || active != 1 {
		t.Fatal("stable better path not chosen")
	}
	if m.Snapshot()[1].State != "VERIFYING" {
		t.Fatal("probe incorrectly confirms traffic")
	}
	if m.MigrationFallback() != 0 {
		t.Fatal("healthy old path lost before new traffic confirmation")
	}
	m.ConfirmTraffic("ru-02", now.Add(6*time.Second))
	if m.MigrationFallback() != -1 {
		t.Fatal("overlap continued after new path confirmation")
	}
	if m.Snapshot()[1].State != "ACTIVE" || m.Snapshot()[0].State != "STANDBY" {
		t.Fatal("old path not retained")
	}
}

func TestPathFailureUsesWarmStandbyAndRecoveryCooldown(t *testing.T) {
	m := NewPathManager([]string{"ru-01", "ru-02"}, PathPolicy{})
	now := time.Unix(100, 0)
	m.Observe(0, 1, []time.Duration{time.Millisecond}, now)
	m.Observe(1, 1, []time.Duration{80 * time.Millisecond}, now)
	m.Observe(0, 1, nil, now)
	if !m.Snapshot()[0].Reachable {
		t.Fatal("one failed round should not flap reachability telemetry")
	}
	if active, changed := m.Select(now); !changed || active != 1 {
		t.Fatal("warm standby not selected after complete active probe failure")
	}
	if m.MigrationFallback() != -1 {
		t.Fatal("failed old path incorrectly requested session preservation")
	}
	m.ConfirmTraffic("ru-02", now)
	m.Observe(0, 1, []time.Duration{time.Millisecond}, now.Add(time.Second))
	m.Select(now.Add(2 * time.Second))
	if active, changed := m.Select(now.Add(8 * time.Second)); changed || active != 1 {
		t.Fatal("recovery cooldown ignored")
	}
	// Even during cooldown a recovered path is useful when every other path dies.
	m.Observe(1, 1, nil, now.Add(9*time.Second))
	m.Observe(1, 1, nil, now.Add(9*time.Second))
	if active, changed := m.Select(now.Add(9 * time.Second)); !changed || active != 0 {
		t.Fatal("last viable path excluded by cooldown")
	}
}

func TestPathMigrationRollsBackUnconfirmedTrafficButNotIdle(t *testing.T) {
	m := NewPathManager([]string{"old", "new"}, PathPolicy{})
	now := time.Unix(100, 0)
	m.Observe(0, 1, []time.Duration{100 * time.Millisecond}, now)
	m.Observe(1, 1, []time.Duration{time.Millisecond}, now)
	m.Select(now)
	m.Select(now.Add(6 * time.Second))
	if active, _ := m.Select(now.Add(time.Minute)); active != 1 {
		t.Fatal("idle migration rolled back")
	}
	m.MarkSent(1, now.Add(time.Minute))
	if active, changed := m.Select(now.Add(time.Minute + 3*time.Second)); !changed || active != 0 {
		t.Fatal("blackhole migration not rolled back")
	}
}

func TestOnlyWireGuardDataConfirmsMigration(t *testing.T) {
	for _, kind := range []byte{1, 2, 3, 4} {
		packet := make([]byte, 148)
		packet[0] = kind
		if isWireGuardTransportData(packet) != (kind == 4) {
			t.Fatalf("wrong packet classification: %d", kind)
		}
	}
	if isWireGuardTransportData([]byte{4, 0, 0, 0}) {
		t.Fatal("truncated data confirmed migration")
	}
}
