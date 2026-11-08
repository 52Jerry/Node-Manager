package socks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/common/varbin"
	upstream "github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type authTestClock struct{ nanos atomic.Int64 }

func authTestBreaker() (*authBreaker, *authTestClock) {
	clock := &authTestClock{}
	clock.nanos.Store(time.Now().UnixNano())
	breaker := newAuthBreaker()
	breaker.clock = func() time.Time { return time.Unix(0, clock.nanos.Load()) }
	return breaker, clock
}

func (c *authTestClock) advance(duration time.Duration) { c.nanos.Add(int64(duration)) }

type authTestServer struct {
	listener    net.Listener
	udp         net.PacketConn
	mode        atomic.Int32 // 0 rejects; 1 accepts; 2 closes before auth response.
	mu          sync.Mutex
	calls       map[string]int
	connections map[net.Conn]bool
	gate        chan struct{}
	requests    chan struct{}
	wait        sync.WaitGroup
}

func newAuthTestServer(t *testing.T) *authTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := &authTestServer{listener: listener, udp: udp, calls: make(map[string]int), connections: make(map[net.Conn]bool), requests: make(chan struct{}, 4096)}
	server.wait.Add(1)
	go func() {
		defer server.wait.Done()
		for {
			conn, acceptError := listener.Accept()
			if acceptError != nil {
				return
			}
			server.mu.Lock()
			server.connections[conn] = true
			server.mu.Unlock()
			server.wait.Add(1)
			go server.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		_ = udp.Close()
		server.mu.Lock()
		for conn := range server.connections {
			_ = conn.Close()
		}
		if server.gate != nil {
			close(server.gate)
			server.gate = nil
		}
		server.mu.Unlock()
		server.wait.Wait()
	})
	return server
}

func (s *authTestServer) serve(conn net.Conn) {
	defer s.wait.Done()
	defer func() { _ = conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := varbin.StubReader(conn)
	if _, err := socks5.ReadAuthRequest(reader); err != nil {
		return
	}
	if socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeUsernamePassword}) != nil {
		return
	}
	credentials, err := socks5.ReadUsernamePasswordAuthRequest(reader)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.calls[credentials.Username]++
	gate := s.gate
	s.mu.Unlock()
	s.requests <- struct{}{}
	if gate != nil {
		<-gate
	}
	mode := s.mode.Load()
	if mode == 2 {
		return
	}
	status := byte(0)
	if mode == 0 && credentials.Username != "healthy-account" {
		status = 1
	}
	if socks5.WriteUsernamePasswordAuthResponse(conn, socks5.UsernamePasswordAuthResponse{Status: status}) != nil || status != 0 {
		return
	}
	request, err := socks5.ReadRequest(reader)
	if err != nil {
		return
	}
	bind := M.SocksaddrFromNet(s.udp.LocalAddr())
	reply := byte(0)
	if mode == 3 {
		reply = socks5.ReplyCodeConnectionRefused
	}
	if socks5.WriteResponse(conn, socks5.Response{ReplyCode: reply, Bind: bind}) != nil || reply != 0 {
		return
	}
	if request.Command == socks5.CommandConnect {
		_, _ = io.Copy(conn, conn)
	} else {
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (s *authTestServer) count(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[user]
}

func (s *authTestServer) block() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = make(chan struct{})
}

func (s *authTestServer) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate != nil {
		close(s.gate)
		s.gate = nil
	}
}

func (s *authTestServer) client(breaker *authBreaker, user, password string) *upstream.Client {
	server := M.SocksaddrFromNet(s.listener.Addr())
	return upstream.NewClient(&authBreakerDialer{Dialer: N.SystemDialer, breaker: breaker, identity: newAuthCircuitIdentity(server.Addr.String(), server.Port, user, password), server: server}, server, upstream.Version5, user, password)
}

var authTestDestination = M.ParseSocksaddr("203.0.113.10:443")

func runAuthParallel(t *testing.T, count int, attempt func() error) []error {
	t.Helper()
	var wait sync.WaitGroup
	results := make([]error, count)
	start := make(chan struct{})
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) { defer wait.Done(); <-start; results[index] = attempt() }(index)
	}
	close(start)
	wait.Wait()
	return results
}

func authTCPAttempt(client *upstream.Client) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, "tcp", authTestDestination)
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}
}

func TestAuthBreakerConcurrentRejectionsStopRealAuthentication(t *testing.T) {
	server := newAuthTestServer(t)
	breaker, _ := authTestBreaker()
	client := server.client(breaker, "failing-account", "private-value")
	for _, err := range runAuthParallel(t, 200, authTCPAttempt(client)) {
		if err == nil {
			t.Fatal("rejected authentication unexpectedly succeeded")
		}
	}
	if actual := server.count("failing-account"); actual != 3 {
		t.Fatalf("actual upstream auth calls=%d, want 3", actual)
	}
	for _, err := range runAuthParallel(t, 200, authTCPAttempt(client)) {
		if !isAuthCircuitSuppressed(err) {
			t.Fatalf("cooldown must reject locally: %v", err)
		}
	}
	if actual := server.count("failing-account"); actual != 3 {
		t.Fatalf("cooldown made extra upstream calls: %d", actual)
	}
	if err := authTCPAttempt(server.client(breaker, "healthy-account", "other-value"))(); err != nil {
		t.Fatalf("same endpoint's healthy account affected: %v", err)
	}
	if got := breaker.snapshot().Circuits; len(got) != 1 || got[0].State != authCircuitOpen || got[0].TotalAuthFailures != 3 || got[0].Suppressed != 397 {
		t.Fatalf("unexpected aggregate snapshot: %+v", got)
	}
}

func TestAuthBreakerHalfOpenSingleFlightAndRecovery(t *testing.T) {
	server := newAuthTestServer(t)
	breaker, clock := authTestBreaker()
	client := server.client(breaker, "recoverable-account", "private-value")
	for index := 0; index < 3; index++ {
		_ = authTCPAttempt(client)()
	}
	clock.advance(301 * time.Second)
	server.mode.Store(1)
	server.block()
	for len(server.requests) > 0 {
		<-server.requests
	}
	done := make(chan error, 1)
	go func() { done <- authTCPAttempt(client)() }()
	select {
	case <-server.requests:
	case <-time.After(time.Second):
		t.Fatal("half-open probe not admitted")
	}
	for _, err := range runAuthParallel(t, 100, authTCPAttempt(client)) {
		if !errors.Is(err, errAuthCircuitProbe) {
			t.Fatalf("additional probe admitted: %v", err)
		}
	}
	if got := server.count("recoverable-account"); got != 4 {
		t.Fatalf("half-open auth count=%d, want 4 total", got)
	}
	server.release()
	if err := <-done; err != nil {
		t.Fatalf("recovery probe: %v", err)
	}
	state := breaker.snapshot().Circuits[0]
	if state.State != authCircuitClosed || state.ConsecutiveFailures != 0 || state.NextProbeAtUnix != 0 {
		t.Fatalf("not recovered: %+v", state)
	}
	for _, err := range runAuthParallel(t, 40, authTCPAttempt(client)) {
		if err != nil {
			t.Fatalf("healthy traffic queued incorrectly: %v", err)
		}
	}
}

func TestAuthBreakerBackoffAndUnknownProbeDoesNotCountAsAuthFailure(t *testing.T) {
	breaker, clock := authTestBreaker()
	identity := newAuthCircuitIdentity("192.0.2.1", 1080, "a", "b")
	for index := 0; index < 3; index++ {
		permit, err := breaker.acquire(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		permit.finish(authRejected)
	}
	for _, seconds := range []int64{600, 1200, 1800, 1800} {
		clock.advance(24 * time.Hour)
		permit, err := breaker.acquire(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		permit.finish(authRejected)
		row := breaker.snapshot().Circuits[0]
		if got := row.NextProbeAtUnix - breaker.clock().Unix(); got != seconds {
			t.Fatalf("backoff=%d, want %d", got, seconds)
		}
	}
	prior := breaker.snapshot().Circuits[0].TotalAuthFailures
	clock.advance(time.Hour)
	permit, err := breaker.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	permit.finish(authUnknown)
	row := breaker.snapshot().Circuits[0]
	if row.State != authCircuitOpen || row.TotalAuthFailures != prior || row.NextProbeAtUnix-breaker.clock().Unix() != 1800 {
		t.Fatalf("unknown result treated as auth rejection or recovery: %+v", row)
	}
}

func TestAuthBreakerWindowCredentialIsolationAndOldResults(t *testing.T) {
	breaker, clock := authTestBreaker()
	identity := newAuthCircuitIdentity("192.0.2.2", 1080, "a", "secret")
	for index := 0; index < 2; index++ {
		permit, _ := breaker.acquire(context.Background(), identity)
		permit.finish(authRejected)
	}
	clock.advance(31 * time.Second)
	permit, err := breaker.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	permit.finish(authRejected)
	row := breaker.snapshot().Circuits[0]
	if row.State != authCircuitClosed || row.ConsecutiveFailures != 1 {
		t.Fatalf("old failures crossed window: %+v", row)
	}
	for index := 0; index < 2; index++ {
		permit, _ := breaker.acquire(context.Background(), identity)
		permit.finish(authRejected)
	}
	for _, other := range []authCircuitIdentity{
		newAuthCircuitIdentity("192.0.2.2", 1080, "a", "new-secret"),
		newAuthCircuitIdentity("192.0.2.2", 1080, "other-account", "secret"),
		newAuthCircuitIdentity("192.0.2.2", 1081, "a", "secret"),
	} {
		permit, acquireError := breaker.acquire(context.Background(), other)
		if acquireError != nil {
			t.Fatal(acquireError)
		}
		permit.finish(authAccepted)
	}
	// Simulate one older accepted handshake finishing after other trusted
	// negotiations have opened the circuit. It must not clear the open state.
	clock.advance(time.Hour)
	probe, _ := breaker.acquire(context.Background(), identity)
	probe.finish(authAccepted)
	old := make([]*authPermit, 4)
	for index := range old {
		old[index], _ = breaker.acquire(context.Background(), identity)
	}
	for index := 0; index < 3; index++ {
		old[index].finish(authRejected)
	}
	old[3].finish(authAccepted)
	if breaker.circuits[identity.key].state != authCircuitOpen {
		t.Fatal("late success cleared a newer circuit")
	}
}

func TestAuthBreakerPendingAuthenticationCancellationAndHealthyAdmissionQueue(t *testing.T) {
	breaker, _ := authTestBreaker()
	identity := newAuthCircuitIdentity("192.0.2.3", 1080, "a", "b")
	first, _ := breaker.acquire(context.Background(), identity)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := breaker.acquire(ctx, identity); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending caller must wait cancellably: %v", err)
	}
	first.finish(authAccepted)
	permits := make([]*authPermit, authTrustedParallel)
	for index := range permits {
		permits[index], _ = breaker.acquire(context.Background(), identity)
	}
	queued := make(chan *authPermit, 1)
	go func() { permit, _ := breaker.acquire(context.Background(), identity); queued <- permit }()
	select {
	case <-queued:
		t.Fatal("healthy auth concurrency bound bypassed")
	case <-time.After(20 * time.Millisecond):
	}
	permits[0].finish(authAccepted)
	select {
	case permit := <-queued:
		if permit == nil {
			t.Fatal("healthy queue rejected")
		}
		permit.finish(authAccepted)
	case <-time.After(time.Second):
		t.Fatal("healthy queue did not resume")
	}
	for _, permit := range permits[1:] {
		permit.finish(authAccepted)
	}
	if breaker.circuits[identity.key].suppressed != 0 {
		t.Fatal("healthy queue counted as circuit suppression")
	}
}

func TestAuthBreakerContextCancelsWireHandshakeAndReleasesPermit(t *testing.T) {
	server := newAuthTestServer(t)
	server.block()
	breaker, _ := authTestBreaker()
	client := server.client(breaker, "blocked-auth", "private-value")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(ctx, "tcp", authTestDestination)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case <-server.requests:
	case <-time.After(time.Second):
		t.Fatal("auth not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("context did not interrupt pending auth")
	}
	server.release()
	for _, circuit := range breaker.circuits {
		if circuit.inFlight != 0 || circuit.totalFailures != 0 {
			t.Fatalf("cancellation misclassified: %+v", circuit)
		}
	}
}

func TestAuthBreakerTCPUDPAndUoTShareProtection(t *testing.T) {
	server := newAuthTestServer(t)
	breaker, _ := authTestBreaker()
	client := server.client(breaker, "shared-protocol-account", "private-value")
	uotClient := &uot.Client{Dialer: client}
	attempts := []func() error{
		authTCPAttempt(client),
		func() error {
			conn, err := client.DialContext(context.Background(), "udp", authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
		func() error {
			conn, err := client.ListenPacket(context.Background(), authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
		func() error {
			conn, err := uotClient.DialContext(context.Background(), "udp", authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
		func() error {
			conn, err := uotClient.ListenPacket(context.Background(), authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
	}
	for _, attempt := range attempts {
		if attempt() == nil {
			t.Fatal("rejected protocol succeeded")
		}
	}
	if got := server.count("shared-protocol-account"); got != 3 {
		t.Fatalf("protocol paths bypassed guard: %d", got)
	}
	server.mode.Store(1)
	for _, attempt := range []func() error{
		func() error {
			conn, err := server.client(breaker, "healthy-account", "other").ListenPacket(context.Background(), authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
		func() error {
			client := &uot.Client{Dialer: server.client(breaker, "healthy-account", "other")}
			conn, err := client.ListenPacket(context.Background(), authTestDestination)
			if conn != nil {
				_ = conn.Close()
			}
			return err
		},
	} {
		if err := attempt(); err != nil {
			t.Fatalf("healthy UDP/UoT broken: %v", err)
		}
	}
}

func TestAuthBreakerDoesNotClassifyEOFOrDestinationErrors(t *testing.T) {
	server := newAuthTestServer(t)
	server.mode.Store(2)
	breaker, _ := authTestBreaker()
	client := server.client(breaker, "eof-account", "private-value")
	for index := 0; index < 6; index++ {
		if authTCPAttempt(client)() == nil {
			t.Fatal("EOF succeeded")
		}
	}
	if got := breaker.snapshot().Circuits; len(got) != 0 {
		t.Fatalf("EOF counted as auth refusal: %+v", got)
	}
	server.mode.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := client.DialContext(ctx, "tcp", authTestDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	observed, ok := conn.(*authObservedConn)
	if !ok || !observed.ReaderReplaceable() || !observed.WriterReplaceable() || observed.Upstream() == nil {
		t.Fatal("healthy data path cannot unwrap authentication observer")
	}
	cancel() // A completed auth observation must not own the data connection.
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err = io.ReadFull(conn, data); err != nil || string(data) != "echo" {
		t.Fatalf("data path altered: %q %v", data, err)
	}
}

func TestAuthBreakerObserverOnlyRecognizesRFC1929Frames(t *testing.T) {
	for _, item := range []struct {
		name    string
		frames  [][]byte
		outcome authOutcome
	}{
		{"fragmented-rejection", [][]byte{{5}, {2}, {1}, {2}}, authRejected},
		{"success-followed-by-payload", [][]byte{{5, 2, 1, 0, 5, 1, 0}}, authAccepted},
		{"no-auth-success", [][]byte{{5, 0}}, authAccepted},
		{"method-rejected", [][]byte{{5, 255}}, authUnknown},
		{"invalid-version", [][]byte{{4, 2, 1, 1}}, authUnknown},
		{"invalid-rfc1929-version", [][]byte{{5, 2, 2, 1}}, authUnknown},
		{"incomplete-frame", [][]byte{{5, 2, 1}}, authUnknown},
	} {
		t.Run(item.name, func(t *testing.T) {
			breaker, _ := authTestBreaker()
			identity := newAuthCircuitIdentity("192.0.2.4", 1080, "a", "b")
			permit, _ := breaker.acquire(context.Background(), identity)
			observed := &authObservedConn{permit: permit}
			for _, frame := range item.frames {
				observed.observe(frame)
			}
			observed.finish(authUnknown)
			circuit := breaker.circuits[identity.key]
			if (circuit.totalFailures == 1) != (item.outcome == authRejected) || circuit.trusted != (item.outcome == authAccepted) || circuit.inFlight != 0 {
				t.Fatalf("frame misclassified: %+v", circuit)
			}
		})
	}
}

func TestAuthBreakerDestinationRefusalIsNotAuthenticationFailure(t *testing.T) {
	server := newAuthTestServer(t)
	server.mode.Store(3)
	breaker, _ := authTestBreaker()
	client := server.client(breaker, "valid-auth-destination-refused", "private-value")
	for index := 0; index < 6; index++ {
		if err := authTCPAttempt(client)(); err == nil || isAuthCircuitSuppressed(err) {
			t.Fatalf("unexpected destination refusal: %v", err)
		}
	}
	if rows := breaker.snapshot().Circuits; len(rows) != 0 {
		t.Fatalf("SOCKS CONNECT refusal misclassified as auth: %+v", rows)
	}
}

func TestAuthBreakerHandshakeTimeoutReleasesPermitWithoutFalseFailure(t *testing.T) {
	server := newAuthTestServer(t)
	server.block()
	breaker, _ := authTestBreaker()
	endpoint := M.SocksaddrFromNet(server.listener.Addr())
	dialer := &authBreakerDialer{Dialer: N.SystemDialer, breaker: breaker, identity: newAuthCircuitIdentity(endpoint.Addr.String(), endpoint.Port, "timeout-account", "private-value"), server: endpoint, handshakeTimeout: 30 * time.Millisecond}
	client := upstream.NewClient(dialer, endpoint, upstream.Version5, "timeout-account", "private-value")
	started := time.Now()
	if err := authTCPAttempt(client)(); err == nil {
		t.Fatal("stalled authentication unexpectedly succeeded")
	}
	if time.Since(started) > time.Second {
		t.Fatal("authentication stage timeout did not bound stalled probe")
	}
	server.release()
	for _, circuit := range breaker.circuits {
		if circuit.inFlight != 0 || circuit.totalFailures != 0 {
			t.Fatal("timeout leaked a permit or counted as auth rejection")
		}
	}
}

func TestAuthBreakerSnapshotBoundsDoNotEvictProtection(t *testing.T) {
	breaker, _ := authTestBreaker()
	for index := 0; index < 8200; index++ {
		identity := newAuthCircuitIdentity("192.0.2.50", 1080, "account-"+string(rune(index)), "private-value")
		permit, err := breaker.acquire(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		permit.finish(authRejected)
	}
	state := breaker.snapshot()
	if len(state.Circuits) != 8192 || state.TrackedCircuits != 8200 || !state.DiagnosticsTruncated || state.OmittedCircuits != 8 {
		t.Fatalf("diagnostic bound mismatch: %d/%d/%d", len(state.Circuits), state.TrackedCircuits, state.OmittedCircuits)
	}
}

func TestAuthBreakerCapacityDoesNotEvictOpenCircuit(t *testing.T) {
	breaker, clock := authTestBreaker()
	breaker.maxCircuits = 1
	identity := newAuthCircuitIdentity("192.0.2.5", 1080, "a", "b")
	for index := 0; index < 3; index++ {
		permit, _ := breaker.acquire(context.Background(), identity)
		permit.finish(authRejected)
	}
	clock.advance(2 * time.Hour)
	other := newAuthCircuitIdentity("192.0.2.5", 1080, "other", "b")
	if _, err := breaker.acquire(context.Background(), other); !errors.Is(err, errAuthCircuitCapacity) {
		t.Fatalf("open entry evicted by pressure: %v", err)
	}
	if breaker.circuits[identity.key] == nil {
		t.Fatal("open circuit lost")
	}
}

func writeAuthTestPolicy(t *testing.T, breaker *authBreaker, policy authBreakerPolicy) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(breaker.policyPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	breaker.readPolicy()
}

func TestAuthBreakerRuntimePolicyDefaultsLastGoodAndVersionFencing(t *testing.T) {
	breaker, _ := authTestBreaker()
	breaker.policyPath = filepath.Join(t.TempDir(), "policy.json")
	breaker.readPolicy()
	if !breaker.policy.Enabled {
		t.Fatal("missing policy must default enabled")
	}
	policy := defaultAuthBreakerPolicy()
	policy.Revision = 2
	writeAuthTestPolicy(t, breaker, policy)
	if err := os.WriteFile(breaker.policyPath, []byte(`{"enabled":false`), 0600); err != nil {
		t.Fatal(err)
	}
	breaker.readPolicy()
	if !breaker.policy.Enabled || breaker.policyError != "BREAKER_POLICY_INVALID" {
		t.Fatal("bad file changed last-good protection")
	}
	policy.Revision = 1
	policy.Enabled = false
	writeAuthTestPolicy(t, breaker, policy)
	if !breaker.policy.Enabled || breaker.policyError != "BREAKER_POLICY_UNAVAILABLE" {
		t.Fatal("older revision accepted")
	}
	policy.Revision = 2
	writeAuthTestPolicy(t, breaker, policy)
	if !breaker.policy.Enabled || breaker.policyError != "BREAKER_POLICY_UNAVAILABLE" {
		t.Fatal("same-revision different settings accepted")
	}
	policy.Revision = 3
	writeAuthTestPolicy(t, breaker, policy)
	if breaker.policy.Enabled {
		t.Fatal("explicit disable not applied")
	}
	permit, err := breaker.acquire(context.Background(), newAuthCircuitIdentity("192.0.2.6", 1080, "a", "b"))
	if err != nil || permit != nil {
		t.Fatal("disabled policy still gates authentication")
	}
}

func TestAuthBreakerManualProbeIsIdempotentAndNeverCreatesParallelProbe(t *testing.T) {
	breaker, clock := authTestBreaker()
	breaker.policyPath = filepath.Join(t.TempDir(), "policy.json")
	identity := newAuthCircuitIdentity("192.0.2.7", 1080, "a", "b")
	for index := 0; index < 3; index++ {
		permit, _ := breaker.acquire(context.Background(), identity)
		permit.finish(authRejected)
	}
	id := breaker.circuits[identity.key].id
	policy := defaultAuthBreakerPolicy()
	policy.Revision = 1
	policy.ProbeRequests = []authProbeRequest{{ID: id, RequestID: "one", RequestedAtUnix: clock.nanos.Load() / int64(time.Second)}}
	writeAuthTestPolicy(t, breaker, policy)
	permit, err := breaker.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal("manual probe not admitted", err)
	}
	policy.Revision = 2
	policy.ProbeRequests = append(policy.ProbeRequests, authProbeRequest{ID: id, RequestID: "two", RequestedAtUnix: clock.nanos.Load() / int64(time.Second)})
	writeAuthTestPolicy(t, breaker, policy)
	if _, err = breaker.acquire(context.Background(), identity); !errors.Is(err, errAuthCircuitProbe) {
		t.Fatal("manual operation bypassed in-flight probe")
	}
	permit.finish(authRejected)
	before := breaker.circuits[identity.key].nextProbe
	policy.Revision = 3
	writeAuthTestPolicy(t, breaker, policy)
	if !breaker.circuits[identity.key].nextProbe.Equal(before) {
		t.Fatal("duplicate request ID released circuit again")
	}
}

func TestAuthBreakerDiagnosticsDoNotExposeCredentialOrPrivateDigest(t *testing.T) {
	breaker, _ := authTestBreaker()
	username, password := "secret-user-value", "secret-password-value"
	identity := newAuthCircuitIdentity("192.0.2.8", 1080, username, password)
	permit, _ := breaker.acquire(context.Background(), identity)
	permit.finish(authRejected)
	data, err := json.Marshal(breaker.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{username, password, hex.EncodeToString(identity.key[:])} {
		if strings.Contains(string(data), private) {
			t.Fatal("diagnostic leaks credential material")
		}
	}
	breaker.stateDir = t.TempDir()
	if err = breaker.writeState(); err != nil {
		t.Fatal("write PID state:", err)
	}
	files, err := filepath.Glob(filepath.Join(breaker.stateDir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("no atomic PID state file", err)
	}
	var snapshot authBreakerSnapshot
	data, err = os.ReadFile(files[0])
	if err != nil || json.Unmarshal(data, &snapshot) != nil || snapshot.InstanceID == "" || snapshot.SchemaVersion != 1 || snapshot.PID != os.Getpid() {
		t.Fatal("invalid process snapshot", err)
	}
}

func TestAuthBreakerConfiguredConstructionIsReadOnly(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.json")
	stateDir := filepath.Join(root, "state")
	t.Setenv("NIUSU_UPSTREAM_AUTH_BREAKER_CONFIG", policyPath)
	t.Setenv("NIUSU_UPSTREAM_AUTH_BREAKER_STATE_DIR", stateDir)
	policy := defaultAuthBreakerPolicy()
	policy.Revision = 4
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(policyPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	breaker := configuredAuthBreaker()
	if !breaker.policy.Enabled || breaker.policy.Revision != 4 || breaker.maintenanceStarted {
		t.Fatal("construction did not read policy or unexpectedly started maintenance")
	}
	time.Sleep(20 * time.Millisecond)
	if _, err = os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatal("configuration-only construction wrote a state directory")
	}
	current, err := os.ReadFile(policyPath)
	if err != nil || string(current) != string(data) {
		t.Fatal("construction changed policy")
	}
	bare, _ := authTestBreaker()
	bare.startMaintenance()
	if bare.maintenanceStarted {
		t.Fatal("bare test manager started I/O maintenance")
	}
}

func TestAuthBreakerRuntimeStartAndActualDialInitializeMaintenanceOnce(t *testing.T) {
	for _, fromDial := range []bool{false, true} {
		name := "explicit-run"
		if fromDial {
			name = "actual-library-dial"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("NIUSU_UPSTREAM_AUTH_BREAKER_CONFIG", filepath.Join(root, "policy.json"))
			t.Setenv("NIUSU_UPSTREAM_AUTH_BREAKER_STATE_DIR", filepath.Join(root, "state"))
			breaker := configuredAuthBreaker()
			defer close(breaker.maintenanceStop)
			if fromDial {
				server := newAuthTestServer(t)
				if err := authTCPAttempt(server.client(breaker, "healthy-account", "private-value"))(); err != nil {
					t.Fatal(err)
				}
			} else {
				var wait sync.WaitGroup
				for index := 0; index < 20; index++ {
					wait.Add(1)
					go func() { defer wait.Done(); breaker.startMaintenance() }()
				}
				wait.Wait()
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				files, _ := filepath.Glob(filepath.Join(breaker.stateDir, "*.json"))
				if len(files) == 1 {
					breaker.mu.Lock()
					started := breaker.maintenanceStarted
					breaker.mu.Unlock()
					if !started {
						t.Fatal("state without runtime maintenance")
					}
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Fatal("runtime heartbeat was not started")
		})
	}
}
