package socks

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type authProbeRequest struct {
	ID              string `json:"id"`
	RequestID       string `json:"requestId"`
	RequestedAtUnix int64  `json:"requestedAtUnix"`
}

type authBreakerPolicy struct {
	SchemaVersion      int                `json:"schemaVersion"`
	Revision           int64              `json:"revision"`
	Enabled            bool               `json:"enabled"`
	Threshold          int                `json:"threshold"`
	WindowSeconds      int                `json:"windowSeconds"`
	CooldownSeconds    int                `json:"cooldownSeconds"`
	MaxCooldownSeconds int                `json:"maxCooldownSeconds"`
	ProbeRequests      []authProbeRequest `json:"probeRequests,omitempty"`
}

func defaultAuthBreakerPolicy() authBreakerPolicy {
	return authBreakerPolicy{SchemaVersion: 1, Enabled: true, Threshold: 3, WindowSeconds: 30, CooldownSeconds: 300, MaxCooldownSeconds: 1800}
}

func (p authBreakerPolicy) valid() bool {
	if p.SchemaVersion != 1 || p.Revision < 0 || p.Threshold < 1 || p.Threshold > 100 || p.WindowSeconds < 1 || p.WindowSeconds > 3600 || p.CooldownSeconds < 1 || p.CooldownSeconds > 86400 || p.MaxCooldownSeconds < p.CooldownSeconds || p.MaxCooldownSeconds > 86400 || len(p.ProbeRequests) > 512 {
		return false
	}
	for _, request := range p.ProbeRequests {
		if request.ID == "" || len(request.ID) > 128 || request.RequestID == "" || len(request.RequestID) > 128 || request.RequestedAtUnix <= 0 {
			return false
		}
	}
	return true
}

var globalAuthBreaker struct {
	once  sync.Once
	value *authBreaker
}

// StartUpstreamAuthBreaker starts the policy heartbeat even for a running core
// without any authenticated SOCKS outbound. Call from the real core lifecycle,
// rather than package init, so configuration-only CLI commands stay read-only.
func StartUpstreamAuthBreaker() { sharedAuthBreaker().startMaintenance() }

func sharedAuthBreaker() *authBreaker {
	globalAuthBreaker.once.Do(func() {
		globalAuthBreaker.value = configuredAuthBreaker()
	})
	return globalAuthBreaker.value
}

// Construction is deliberately read-only: sing-box check constructs outbounds
// but must not leave runtime state files or policy-maintenance goroutines.
func configuredAuthBreaker() *authBreaker {
	manager := newAuthBreaker()
	manager.policyPath = os.Getenv("NIUSU_UPSTREAM_AUTH_BREAKER_CONFIG")
	if manager.policyPath == "" {
		manager.policyPath = "/var/lib/node-manager/upstream-auth-breaker.json"
	}
	manager.stateDir = os.Getenv("NIUSU_UPSTREAM_AUTH_BREAKER_STATE_DIR")
	if manager.stateDir == "" {
		manager.stateDir = "/var/lib/node-manager/upstream-auth-breaker-state"
	}
	manager.startTicks = selfAuthProcessTicks()
	manager.readPolicy()
	return manager
}

func (b *authBreaker) startMaintenance() {
	// Bare test managers have no configured I/O paths. Library users get the
	// same lazy initialization on first actual protected dial as the run hook.
	if b.policyPath == "" || b.stateDir == "" {
		return
	}
	b.maintenanceOnce.Do(func() {
		b.mu.Lock()
		b.maintenanceStarted = true
		b.mu.Unlock()
		go b.maintain()
	})
}

func selfAuthProcessTicks() uint64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0
	}
	ticks, _ := strconv.ParseUint(fields[19], 10, 64)
	return ticks
}

func (b *authBreaker) maintain() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	b.writeState()
	for tick := 1; ; tick++ {
		select {
		case <-b.maintenanceStop:
			return
		case <-ticker.C:
		}
		b.readPolicy()
		if tick%5 == 0 {
			b.mu.Lock()
			b.collectIdleLocked(b.clock(), false)
			b.mu.Unlock()
			b.writeState()
		}
	}
}

func (b *authBreaker) readPolicy() {
	var data []byte
	file, err := os.Open(b.policyPath)
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(file, 1024*1024+1))
		_ = file.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.policyReadAt = now
	if os.IsNotExist(err) {
		// An absent file uses the enabled default on first start. Deleting an
		// already applied file must not silently reset an operator's last policy.
		b.policyError = ""
		if b.hasPolicyDigest {
			b.policyError = "BREAKER_POLICY_UNAVAILABLE"
		}
		return
	}
	if err != nil {
		b.policyError = "BREAKER_POLICY_READ_FAILED"
		return
	}
	if len(data) > 1024*1024 {
		b.policyError = "BREAKER_POLICY_INVALID"
		return
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		b.policyError = "BREAKER_POLICY_INVALID"
		return
	}
	digest := sha256.Sum256(data)
	if b.hasPolicyDigest && digest == b.lastPolicyDigest {
		b.policyError = ""
		return
	}
	policy := defaultAuthBreakerPolicy()
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&policy) != nil || !policy.valid() {
		b.policyError = "BREAKER_POLICY_INVALID"
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		b.policyError = "BREAKER_POLICY_INVALID"
		return
	}
	if policy.Revision < b.policy.Revision {
		b.policyError = "BREAKER_POLICY_UNAVAILABLE"
		return
	}
	// Same revision cannot change protection settings. Probe requests are a
	// separate idempotent control channel and may append under that revision.
	if b.hasPolicyDigest && policy.Revision == b.policy.Revision && !sameAuthPolicySettings(policy, b.policy) {
		b.policyError = "BREAKER_POLICY_UNAVAILABLE"
		return
	}
	b.policy = policy
	b.lastPolicyDigest = digest
	b.hasPolicyDigest = true
	b.policyError = ""
	for _, request := range policy.ProbeRequests {
		if _, seen := b.seenProbeRequests[request.RequestID]; seen {
			continue
		}
		// Old control records must not unexpectedly release a circuit after a
		// core restart. A queued request is useful for five minutes only.
		age := now.Sub(time.Unix(request.RequestedAtUnix, 0))
		if age < -time.Minute || age > 5*time.Minute {
			continue
		}
		b.seenProbeRequests[request.RequestID] = now
		for _, circuit := range b.circuits {
			if circuit.id == request.ID && circuit.state == authCircuitOpen {
				circuit.nextProbe = now
				b.notify(circuit)
				break
			}
		}
	}
	for _, circuit := range b.circuits {
		b.notify(circuit) // Wake cancellable admission waiters on disable.
	}
}

func sameAuthPolicySettings(left, right authBreakerPolicy) bool {
	return left.Enabled == right.Enabled && left.Threshold == right.Threshold && left.WindowSeconds == right.WindowSeconds && left.CooldownSeconds == right.CooldownSeconds && left.MaxCooldownSeconds == right.MaxCooldownSeconds
}

type authCircuitSnapshot struct {
	ID                     string `json:"id"`
	Server                 string `json:"server"`
	Port                   uint16 `json:"port"`
	State                  string `json:"state"`
	ConsecutiveFailures    int    `json:"consecutiveFailures"`
	TotalAuthFailures      uint64 `json:"totalAuthFailures"`
	Suppressed             uint64 `json:"suppressed"`
	OpenedAtUnix           int64  `json:"openedAtUnix"`
	FirstFailureAtUnix     int64  `json:"firstFailureAtUnix"`
	LastFailureAtUnix      int64  `json:"lastFailureAtUnix"`
	LastSuccessAtUnix      int64  `json:"lastSuccessAtUnix"`
	NextProbeAtUnix        int64  `json:"nextProbeAtUnix"`
	InFlightAuthentication int    `json:"inFlightAuthentication"`
}

type authBreakerSnapshot struct {
	SchemaVersion        int                   `json:"schemaVersion"`
	PID                  int                   `json:"pid"`
	InstanceID           string                `json:"instanceId"`
	ProcessStartedAtUnix int64                 `json:"processStartedAtUnix"`
	ProcessStartTicks    uint64                `json:"processStartTicks"`
	ObservedAtUnix       int64                 `json:"observedAtUnix"`
	PolicyReadAtUnix     int64                 `json:"policyReadAtUnix"`
	PolicyRevision       int64                 `json:"policyRevision"`
	PolicyError          string                `json:"policyError"`
	Enabled              bool                  `json:"enabled"`
	TrackedCircuits      int                   `json:"trackedCircuits"`
	DiagnosticsTruncated bool                  `json:"diagnosticsTruncated"`
	OmittedCircuits      int                   `json:"omittedCircuits"`
	Circuits             []authCircuitSnapshot `json:"circuits"`
}

func authUnix(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func (b *authBreaker) snapshot() authBreakerSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot := authBreakerSnapshot{SchemaVersion: 1, PID: os.Getpid(), InstanceID: b.instanceID, ProcessStartedAtUnix: b.startedAt.Unix(), ProcessStartTicks: b.startTicks, ObservedAtUnix: b.clock().Unix(), PolicyReadAtUnix: authUnix(b.policyReadAt), PolicyRevision: b.policy.Revision, PolicyError: b.policyError, Enabled: b.policy.Enabled, TrackedCircuits: len(b.circuits), Circuits: make([]authCircuitSnapshot, 0)}
	for _, circuit := range b.circuits {
		if circuit.totalFailures == 0 && circuit.state == authCircuitClosed && circuit.suppressed == 0 {
			continue
		}
		snapshot.Circuits = append(snapshot.Circuits, authCircuitSnapshot{ID: circuit.id, Server: circuit.identity.server, Port: circuit.identity.port, State: circuit.state, ConsecutiveFailures: circuit.consecutive, TotalAuthFailures: circuit.totalFailures, Suppressed: circuit.suppressed, OpenedAtUnix: authUnix(circuit.openedAt), FirstFailureAtUnix: authUnix(circuit.firstFailure), LastFailureAtUnix: authUnix(circuit.lastFailure), LastSuccessAtUnix: authUnix(circuit.lastSuccess), NextProbeAtUnix: authUnix(circuit.nextProbe), InFlightAuthentication: circuit.inFlight})
	}
	// Prioritize live protection and recent failures when returning a bounded
	// management view. The in-memory guard retains every protected circuit.
	sort.Slice(snapshot.Circuits, func(left, right int) bool {
		a, z := snapshot.Circuits[left], snapshot.Circuits[right]
		if (a.State != authCircuitClosed) != (z.State != authCircuitClosed) {
			return a.State != authCircuitClosed
		}
		if a.LastFailureAtUnix != z.LastFailureAtUnix {
			return a.LastFailureAtUnix > z.LastFailureAtUnix
		}
		return a.ID < z.ID
	})
	if len(snapshot.Circuits) > 8192 {
		snapshot.DiagnosticsTruncated = true
		snapshot.OmittedCircuits = len(snapshot.Circuits) - 8192
		snapshot.Circuits = snapshot.Circuits[:8192]
	}
	return snapshot
}

func (b *authBreaker) writeState() error {
	if b.stateDir == "" {
		return nil
	}
	data, err := json.Marshal(b.snapshot())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(b.stateDir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(b.stateDir, ".state-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	_, writeError := file.Write(data)
	closeError := file.Close()
	if writeError == nil && closeError == nil {
		return os.Rename(name, filepath.Join(b.stateDir, strconv.Itoa(os.Getpid())+".json"))
	}
	if writeError != nil {
		return writeError
	}
	return closeError
}
