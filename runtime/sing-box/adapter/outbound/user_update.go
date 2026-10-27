package outbound

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

// PrepareUserUpdate constructs and starts replacements without publishing them.
// Only dependency-free user outbounds may be replaced; the default is immutable.
func (m *Manager) PrepareUserUpdate(ctx context.Context, router adapter.Router, logger log.Factory, options []option.Outbound, remove []string) (publish func(), abort func(), cleanup func() error, err error) {
	m.access.RLock()
	for _, tag := range remove {
		old, found := m.outboundByTag[tag]
		if !found || old == m.defaultOutbound || len(m.dependByTag[tag]) != 0 || len(old.Dependencies()) != 0 {
			m.access.RUnlock()
			return nil, nil, nil, fmt.Errorf("outbound is shared, default, dependent, or unavailable")
		}
	}
	started, stage := m.started, m.stage
	m.access.RUnlock()
	var prepared []adapter.Outbound
	abort = func() {
		for _, outbound := range prepared {
			_ = common.Close(outbound)
		}
	}
	for _, options := range options {
		if options.Type != "direct" && options.Type != "socks" {
			abort()
			return nil, nil, nil, fmt.Errorf("unsupported user outbound type")
		}
		if _, exists := m.endpoint.Get(options.Tag); exists {
			abort()
			return nil, nil, nil, fmt.Errorf("outbound tag overlaps an endpoint")
		}
		outbound, e := m.registry.CreateOutbound(ctx, router, logger.NewLogger("outbound/"+options.Type+"["+options.Tag+"]"), options.Tag, options.Type, options.Options)
		if e != nil {
			abort()
			return nil, nil, nil, e
		}
		prepared = append(prepared, outbound)
		if len(outbound.Dependencies()) != 0 {
			abort()
			return nil, nil, nil, fmt.Errorf("dynamic user outbounds cannot have dependencies")
		}
		if started {
			for _, start := range adapter.ListStartStages {
				if start > stage {
					break
				}
				if e = adapter.LegacyStart(outbound, start); e != nil {
					abort()
					return nil, nil, nil, e
				}
			}
		}
	}
	var retired []adapter.Outbound
	publish = func() {
		m.access.Lock()
		defer m.access.Unlock()
		removed := make(map[string]bool, len(remove))
		for _, tag := range remove {
			removed[tag] = true
			retired = append(retired, m.outboundByTag[tag])
			delete(m.outboundByTag, tag)
		}
		next := make([]adapter.Outbound, 0, len(m.outbounds)+len(prepared))
		for _, outbound := range m.outbounds {
			if !removed[outbound.Tag()] {
				next = append(next, outbound)
			}
		}
		for _, outbound := range prepared {
			next = append(next, outbound)
			m.outboundByTag[outbound.Tag()] = outbound
		}
		m.outbounds = next
	}
	cleanup = func() error {
		var first error
		for _, outbound := range retired {
			if e := common.Close(outbound); e != nil && first == nil {
				first = e
			}
		}
		return first
	}
	return publish, abort, cleanup, nil
}
