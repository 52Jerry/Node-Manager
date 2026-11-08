package socks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authCircuitClosed   = "CLOSED"
	authCircuitOpen     = "OPEN"
	authCircuitHalfOpen = "HALF_OPEN"
	authCircuitCapacity = 32768
	authTrustedParallel = 8
)

// The route layer recognizes net.ErrClosed and avoids emitting an error log for
// every locally suppressed retry. Operators see aggregate counters instead.
type authCircuitError struct{ reason string }

func (e *authCircuitError) Error() string                          { return e.reason }
func (e *authCircuitError) Unwrap() error                          { return net.ErrClosed }
func (e *authCircuitError) UpstreamAuthenticationSuppressed() bool { return true }

var (
	errAuthCircuitOpen     = &authCircuitError{"upstream SOCKS authentication circuit is open"}
	errAuthCircuitProbe    = &authCircuitError{"upstream SOCKS authentication probe is already running"}
	errAuthCircuitCapacity = &authCircuitError{"upstream SOCKS authentication protection capacity reached"}
)

type authOutcome uint8

const (
	authUnknown authOutcome = iota
	authAccepted
	authRejected
)

type authCircuitIdentity struct {
	key    [32]byte // Never exported to diagnostics, logs or disk.
	server string
	port   uint16
}

func newAuthCircuitIdentity(server string, port uint16, username, password string) authCircuitIdentity {
	hash := sha256.New()
	for _, value := range []string{strings.ToLower(server), strconv.Itoa(int(port)), username, password} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	identity := authCircuitIdentity{server: safeAuthServer(server), port: port}
	copy(identity.key[:], hash.Sum(nil))
	return identity
}

func safeAuthServer(value string) string {
	if value == "" || len(value) > 253 {
		return "invalid-host"
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".:-[]", r)) {
			return "invalid-host"
		}
	}
	return value
}

func authOpaqueID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		// A random failure must not publish a credential-derived identifier.
		return "unavailable"
	}
	return hex.EncodeToString(random[:])
}

type authCircuit struct {
	id            string
	identity      authCircuitIdentity
	state         string
	trusted       bool
	epoch         uint64
	inFlight      int
	consecutive   int
	totalFailures uint64
	suppressed    uint64
	firstFailure  time.Time
	lastFailure   time.Time
	lastSuccess   time.Time
	openedAt      time.Time
	nextProbe     time.Time
	backoff       time.Duration
	lastUsed      time.Time
	changed       chan struct{}
}

type authBreaker struct {
	mu                 sync.Mutex
	policy             authBreakerPolicy
	circuits           map[[32]byte]*authCircuit
	clock              func() time.Time
	policyPath         string
	stateDir           string
	instanceID         string
	startedAt          time.Time
	startTicks         uint64
	policyReadAt       time.Time
	policyError        string
	lastPolicyDigest   [32]byte
	hasPolicyDigest    bool
	seenProbeRequests  map[string]time.Time
	maxCircuits        int
	maintenanceOnce    sync.Once
	maintenanceStop    chan struct{}
	maintenanceStarted bool
}

func newAuthBreaker() *authBreaker {
	return &authBreaker{
		policy:            defaultAuthBreakerPolicy(),
		circuits:          make(map[[32]byte]*authCircuit),
		clock:             time.Now,
		instanceID:        authOpaqueID(),
		startedAt:         time.Now(),
		seenProbeRequests: make(map[string]time.Time),
		maxCircuits:       authCircuitCapacity,
		maintenanceStop:   make(chan struct{}),
	}
}

func (b *authBreaker) notify(circuit *authCircuit) {
	close(circuit.changed)
	circuit.changed = make(chan struct{})
}

type authPermit struct {
	breaker *authBreaker
	circuit *authCircuit
	epoch   uint64
	once    sync.Once
}

func (p *authPermit) finish(outcome authOutcome) {
	if p == nil {
		return
	}
	p.once.Do(func() { p.breaker.complete(p, outcome) })
}

// acquire only covers SOCKS authentication. A successful auth frame releases it
// before destination CONNECT/UDP ASSOCIATE completes or application data flows.
func (b *authBreaker) acquire(ctx context.Context, identity authCircuitIdentity) (*authPermit, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b.mu.Lock()
		if !b.policy.Enabled {
			b.mu.Unlock()
			return nil, nil
		}
		now := b.clock()
		circuit := b.circuits[identity.key]
		if circuit == nil {
			if len(b.circuits) >= b.maxCircuits {
				b.collectIdleLocked(now, true)
			}
			if len(b.circuits) >= b.maxCircuits {
				b.mu.Unlock()
				return nil, errAuthCircuitCapacity
			}
			circuit = &authCircuit{id: authOpaqueID(), identity: identity, state: authCircuitClosed, lastUsed: now, changed: make(chan struct{})}
			b.circuits[identity.key] = circuit
		}
		circuit.lastUsed = now
		if circuit.state == authCircuitOpen {
			if now.Before(circuit.nextProbe) {
				circuit.suppressed++
				b.mu.Unlock()
				return nil, errAuthCircuitOpen
			}
			// Old admitted negotiations must finish before a new probe is allowed.
			if circuit.inFlight != 0 {
				circuit.suppressed++
				b.mu.Unlock()
				return nil, errAuthCircuitProbe
			}
			circuit.state = authCircuitHalfOpen
			circuit.epoch++
		} else if circuit.state == authCircuitHalfOpen {
			circuit.suppressed++
			b.mu.Unlock()
			return nil, errAuthCircuitProbe
		}
		limit := 1
		if circuit.trusted && circuit.consecutive == 0 && circuit.state == authCircuitClosed {
			limit = authTrustedParallel
		}
		if circuit.inFlight < limit {
			circuit.inFlight++
			permit := &authPermit{breaker: b, circuit: circuit, epoch: circuit.epoch}
			b.mu.Unlock()
			return permit, nil
		}
		changed := circuit.changed
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (b *authBreaker) complete(permit *authPermit, outcome authOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	circuit := permit.circuit
	now := b.clock()
	if circuit.inFlight > 0 {
		circuit.inFlight--
	}
	circuit.lastUsed = now
	if outcome == authRejected {
		circuit.totalFailures++
		circuit.lastFailure = now
	}
	// A late result from an earlier epoch cannot override an OPEN or newer probe.
	if permit.epoch != circuit.epoch {
		b.notify(circuit)
		return
	}
	switch outcome {
	case authAccepted:
		circuit.state = authCircuitClosed
		circuit.trusted = true
		circuit.consecutive = 0
		circuit.firstFailure = time.Time{}
		circuit.nextProbe = time.Time{}
		circuit.backoff = 0
		circuit.lastSuccess = now
	case authRejected:
		circuit.trusted = false
		if circuit.consecutive == 0 || now.Sub(circuit.firstFailure) > time.Duration(b.policy.WindowSeconds)*time.Second {
			circuit.consecutive = 0
			circuit.firstFailure = now
		}
		circuit.consecutive++
		if circuit.state == authCircuitHalfOpen || circuit.consecutive >= b.policy.Threshold {
			if circuit.backoff == 0 {
				circuit.backoff = time.Duration(b.policy.CooldownSeconds) * time.Second
			} else {
				circuit.backoff *= 2
			}
			maximum := time.Duration(b.policy.MaxCooldownSeconds) * time.Second
			if circuit.backoff > maximum {
				circuit.backoff = maximum
			}
			circuit.state = authCircuitOpen
			circuit.epoch++
			circuit.openedAt = now
			circuit.nextProbe = now.Add(circuit.backoff)
		}
	case authUnknown:
		if circuit.state == authCircuitHalfOpen {
			// An EOF/timeout is not another auth failure or a recovery proof.
			circuit.state = authCircuitOpen
			circuit.epoch++
			circuit.nextProbe = now.Add(circuit.backoff)
		}
	}
	b.notify(circuit)
}

func (b *authBreaker) collectIdleLocked(now time.Time, capacityPressure bool) {
	idle := time.Hour
	if capacityPressure {
		idle = 5 * time.Minute
	}
	for key, circuit := range b.circuits {
		// OPEN/HALF_OPEN entries are never evicted to let bad credentials bypass
		// protection by filling the cache with unrelated identities.
		if circuit.state == authCircuitClosed && circuit.inFlight == 0 && now.Sub(circuit.lastUsed) > idle {
			delete(b.circuits, key)
		}
	}
	for id, seen := range b.seenProbeRequests {
		if now.Sub(seen) > 24*time.Hour {
			delete(b.seenProbeRequests, id)
		}
	}
}

func isAuthCircuitSuppressed(err error) bool {
	var circuitError *authCircuitError
	return errors.As(err, &circuitError)
}
