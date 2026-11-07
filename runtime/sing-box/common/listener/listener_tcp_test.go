package listener

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

type temporaryAcceptError struct{ onTemporary func() }

func (temporaryAcceptError) Error() string { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool { return false }
func (e temporaryAcceptError) Temporary() bool {
	if e.onTemporary != nil {
		e.onTemporary()
	}
	return true
}

type scriptedTCPListener struct {
	t       *testing.T
	errors  []error
	accepts int
	closes  int
}

func (l *scriptedTCPListener) Accept() (net.Conn, error) {
	if l.accepts >= len(l.errors) {
		l.t.Fatal("Accept called again after the terminal error")
	}
	err := l.errors[l.accepts]
	l.accepts++
	return nil, err
}

func (l *scriptedTCPListener) Close() error { l.closes++; return nil }
func (*scriptedTCPListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestTCPAcceptRetryDelayIsBounded(t *testing.T) {
	var delay time.Duration
	for i, want := range []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000} {
		delay = nextTCPAcceptRetryDelay(delay)
		if delay != want*time.Millisecond {
			t.Fatalf("retry %d = %s, want %s", i, delay, want*time.Millisecond)
		}
	}
}

func TestTCPAcceptStopsOnTerminalError(t *testing.T) {
	for _, terminal := range []error{errors.New("permanent failure"), net.ErrClosed} {
		t.Run(terminal.Error(), func(t *testing.T) {
			source := &scriptedTCPListener{t: t, errors: []error{temporaryAcceptError{}, temporaryAcceptError{}, terminal}}
			listener := &Listener{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), tcpListener: source}
			listener.loopTCPIn()
			if source.accepts != 3 || source.closes != 1 {
				t.Fatalf("accepts=%d closes=%d, want 3 and 1", source.accepts, source.closes)
			}
		})
	}
}

func TestTCPAcceptDoesNotRetryOnShutdownOrCancellation(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		source := &scriptedTCPListener{t: t}
		listener := &Listener{ctx: ctx, logger: log.NewNOPFactory().Logger(), tcpListener: source}
		if shutdown {
			listener.shutdown.Store(true)
		} else {
			cancel()
		}
		listener.loopTCPIn()
		cancel()
		if source.accepts != 0 {
			t.Fatal("closed listener attempted Accept")
		}
	}
}

func TestTCPAcceptCancellationInterruptsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel after Accept's context check, immediately before retry waiting.
	source := &scriptedTCPListener{t: t, errors: []error{temporaryAcceptError{onTemporary: cancel}}}
	listener := &Listener{ctx: ctx, logger: log.NewNOPFactory().Logger(), tcpListener: source}
	listener.loopTCPIn()
	if source.accepts != 1 || source.closes != 0 {
		t.Fatalf("accepts=%d closes=%d after cancellation, want 1 and 0", source.accepts, source.closes)
	}
}
