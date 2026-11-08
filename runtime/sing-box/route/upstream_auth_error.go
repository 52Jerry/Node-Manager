package route

import (
	"context"
	"errors"
)

// Only an explicit protection marker quiets locally suppressed retries. Actual
// upstream authentication failures and unrelated network errors keep their logs.
func upstreamAuthenticationSuppressed(err error) bool {
	var marker interface{ UpstreamAuthenticationSuppressed() bool }
	return errors.As(err, &marker) && marker.UpstreamAuthenticationSuppressed()
}

func (m *ConnectionManager) logOutboundDialError(ctx context.Context, err error) {
	if upstreamAuthenticationSuppressed(err) {
		m.logger.DebugContext(ctx, err)
		return
	}
	m.logger.ErrorContext(ctx, err)
}
