package route

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

type markedAuthProtectionError struct{ suppressed bool }

func (e markedAuthProtectionError) Error() string                          { return "local protection" }
func (e markedAuthProtectionError) UpstreamAuthenticationSuppressed() bool { return e.suppressed }

func TestOnlyExplicitUpstreamProtectionQuietsDialErrors(t *testing.T) {
	cases := []struct {
		err   error
		quiet bool
	}{
		{markedAuthProtectionError{true}, true},
		{fmt.Errorf("wrapped: %w", markedAuthProtectionError{true}), true},
		{errors.Join(net.ErrClosed, markedAuthProtectionError{true}), true},
		{markedAuthProtectionError{false}, false},
		{net.ErrClosed, false},
		{errors.New("socks5: incorrect user name or password"), false},
		{errors.New("connection timed out"), false},
		{nil, false},
	}
	for _, item := range cases {
		if got := upstreamAuthenticationSuppressed(item.err); got != item.quiet {
			t.Errorf("error %T: quiet=%v, want %v", item.err, got, item.quiet)
		}
	}
}
