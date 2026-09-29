package wgshim

import (
	"math"
	"sort"
	"sync"
	"time"
)

// PathPolicy controls selection, not overlay identity or routing policy.
type PathPolicy struct {
	MinimumImprovement    time.Duration
	MinimumStableDuration time.Duration
	FailurePenalty        time.Duration
	RecoveryCooldown      time.Duration
	FailureThreshold      int
}

func (p PathPolicy) defaults() PathPolicy {
	if p.MinimumImprovement <= 0 {
		p.MinimumImprovement = 15 * time.Millisecond
	}
	if p.MinimumStableDuration <= 0 {
		p.MinimumStableDuration = 5 * time.Second
	}
	if p.FailurePenalty <= 0 {
		p.FailurePenalty = 250 * time.Millisecond
	}
	if p.RecoveryCooldown <= 0 {
		p.RecoveryCooldown = 10 * time.Second
	}
	if p.FailureThreshold <= 0 {
		p.FailureThreshold = 2
	}
	return p
}

type PathHealth struct {
	Node                string    `json:"node,omitempty"`
	Endpoint            string    `json:"endpoint"`
	Reachable           bool      `json:"reachable"`
	RTTMS               float64   `json:"rtt_ms"`
	LossPercent         float64   `json:"loss_percent"`
	JitterMS            float64   `json:"jitter_ms"`
	LastSuccess         time.Time `json:"last_success"`
	FailureCount        uint64    `json:"failure_count"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	State               string    `json:"state"`
	LastTraffic         time.Time `json:"last_traffic"`
}

type pathState struct {
	PathHealth
	samples     []bool
	lastRTT     time.Duration
	failedAt    time.Time
	recoveredAt time.Time
}

// PathManager has no access to Device identity, keys, Access or routes. A switch
// changes only the selected already-probed transport endpoint.
type PathManager struct {
	mu               sync.Mutex
	policy           PathPolicy
	paths            []pathState
	active           int
	candidate        int
	candidateSince   time.Time
	migratingFrom    int
	migrationStarted time.Time
}

func NewPathManager(endpoints []string, policy PathPolicy) *PathManager {
	m := &PathManager{policy: policy.defaults(), candidate: -1, migratingFrom: -1}
	for _, endpoint := range endpoints {
		m.paths = append(m.paths, pathState{PathHealth: PathHealth{Endpoint: endpoint}})
	}
	return m
}

// Observe records a completed authenticated probe round. Loss uses a bounded
// rolling window; failure counts are cumulative and RTT/jitter are smoothed.
func (m *PathManager) Observe(index int, sent int, replies []time.Duration, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if index < 0 || index >= len(m.paths) || sent <= 0 {
		return
	}
	p := &m.paths[index]
	if len(replies) > sent {
		replies = replies[:sent]
	}
	for i := 0; i < sent; i++ {
		p.samples = append(p.samples, i < len(replies))
	}
	if len(p.samples) > 32 {
		p.samples = p.samples[len(p.samples)-32:]
	}
	lost := 0
	for _, success := range p.samples {
		if !success {
			lost++
		}
	}
	p.LossPercent = 100 * float64(lost) / float64(len(p.samples))
	p.FailureCount += uint64(sent - len(replies))
	if len(replies) == 0 {
		p.ConsecutiveFailures++
		p.failedAt = now
		if p.ConsecutiveFailures >= m.policy.FailureThreshold {
			p.Reachable = false
		}
		return
	}
	if !p.Reachable && !p.failedAt.IsZero() {
		p.recoveredAt = now
	}
	p.Reachable = true
	p.ConsecutiveFailures = 0
	p.LastSuccess = now
	for _, rtt := range replies {
		if p.lastRTT != 0 {
			p.JitterMS = .75*p.JitterMS + .25*math.Abs(float64(rtt-p.lastRTT)/float64(time.Millisecond))
		}
		p.lastRTT = rtt
	}
	values := append([]time.Duration(nil), replies...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	rtt := float64(values[len(values)/2]) / float64(time.Millisecond)
	if p.RTTMS == 0 {
		p.RTTMS = rtt
	} else {
		p.RTTMS = .75*p.RTTMS + .25*rtt
	}
}

func (m *PathManager) score(p pathState, now time.Time) float64 {
	penalty := 0.0
	if !p.failedAt.IsZero() {
		remaining := 1 - float64(now.Sub(p.failedAt))/float64(m.policy.RecoveryCooldown)
		if remaining > 0 {
			penalty = remaining * float64(m.policy.FailurePenalty) / float64(time.Millisecond)
		}
	}
	return p.RTTMS + 2*p.JitterMS + 3*p.LossPercent + penalty
}

func (m *PathManager) Select(now time.Time) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.paths) == 0 {
		return -1, false
	}
	if m.migratingFrom >= 0 && !m.migrationStarted.IsZero() && now.Sub(m.migrationStarted) > 2*time.Second && m.paths[m.migratingFrom].Reachable {
		failed := &m.paths[m.active]
		failed.failedAt = now
		failed.Reachable = false
		failed.FailureCount++
		m.active = m.migratingFrom
		m.migratingFrom = -1
		m.candidate = -1
		return m.active, true
	}
	best := -1
	// Reachable is intentionally debounced for telemetry, but an active path that
	// just lost an entire authenticated probe round should not hold traffic when
	// an already-warm standby is healthy.
	currentUsable := m.paths[m.active].Reachable && m.paths[m.active].ConsecutiveFailures == 0
	for i, p := range m.paths {
		if !p.Reachable || p.ConsecutiveFailures > 0 {
			continue
		}
		// Cooldown prevents flapping back to a recovered path. A failed active path
		// may use it when it is the only remaining reachable candidate.
		if currentUsable && !p.recoveredAt.IsZero() && now.Sub(p.recoveredAt) < m.policy.RecoveryCooldown {
			continue
		}
		if best < 0 || m.score(p, now) < m.score(m.paths[best], now) {
			best = i
		}
	}
	if best < 0 || best == m.active {
		m.candidate = -1
		return m.active, false
	}
	if currentUsable {
		if m.score(m.paths[m.active], now)-m.score(m.paths[best], now) < float64(m.policy.MinimumImprovement)/float64(time.Millisecond) {
			m.candidate = -1
			return m.active, false
		}
		if m.candidate != best {
			m.candidate = best
			m.candidateSince = now
			return m.active, false
		}
		if now.Sub(m.candidateSince) < m.policy.MinimumStableDuration {
			return m.active, false
		}
	}
	m.migratingFrom = m.active
	m.migrationStarted = time.Time{}
	m.active = best
	m.candidate = -1
	return m.active, true
}

// ConfirmTraffic is separate from probe reachability: a relay can answer probes
// even when the overlay destination behind it is unavailable.
func (m *PathManager) ConfirmTraffic(endpoint string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.paths {
		if m.paths[i].Endpoint == endpoint {
			m.paths[i].LastTraffic = now
			if i == m.active {
				m.migratingFrom = -1
			}
			return
		}
	}
}

func (m *PathManager) Snapshot() []PathHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]PathHealth, len(m.paths))
	for i, p := range m.paths {
		h := p.PathHealth
		h.State = "PROBING"
		if !h.LastSuccess.IsZero() {
			h.State = "FAILED"
		}
		if h.Reachable {
			h.State = "STANDBY"
		}
		if i == m.active {
			h.State = "ACTIVE"
			if m.migratingFrom >= 0 {
				h.State = "VERIFYING"
			}
		}
		result[i] = h
	}
	return result
}

// MarkSent starts the traffic confirmation deadline only when traffic actually
// uses the new path; idle tunnels are not mistaken for blackholes.
func (m *PathManager) MarkSent(index int, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if index == m.active && m.migratingFrom >= 0 && m.migrationStarted.IsZero() {
		m.migrationStarted = now
	}
}

// MigrationFallback returns the still-working previous endpoint while the new
// path is unconfirmed. Failed paths must never delay emergency handoff.
func (m *PathManager) MigrationFallback() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.migratingFrom < 0 {
		return -1
	}
	p := m.paths[m.migratingFrom]
	if !p.Reachable || p.ConsecutiveFailures > 0 {
		return -1
	}
	return m.migratingFrom
}
