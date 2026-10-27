package userstate

import (
	"context"
	"net"
	"sort"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type trafficKey struct{ inbound, user string }
type TrafficCounter struct{ upload, download atomic.Int64 }
type TrafficSnapshot struct {
	Inbound  string `json:"inbound"`
	User     string `json:"user"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

func (m *Manager) counter(metadata adapter.InboundContext) *TrafficCounter {
	if metadata.User == "" {
		return nil
	}
	key := trafficKey{metadata.Inbound, metadata.User}
	m.mu.Lock()
	defer m.mu.Unlock()
	counter := m.counters[key]
	if counter == nil {
		counter = &TrafficCounter{}
		m.counters[key] = counter
	}
	return counter
}
func (m *Manager) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	counter := m.counter(metadata)
	if counter == nil {
		return conn
	}
	return bufio.NewCounterConn(conn, []N.CountFunc{func(n int64) { counter.upload.Add(n) }}, []N.CountFunc{func(n int64) { counter.download.Add(n) }})
}
func (m *Manager) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	counter := m.counter(metadata)
	if counter == nil {
		return conn
	}
	return bufio.NewCounterPacketConn(conn, []N.CountFunc{func(n int64) { counter.upload.Add(n) }}, []N.CountFunc{func(n int64) { counter.download.Add(n) }})
}

// Counters are cumulative for the process lifetime, including closed sessions.
// A collector must pair them with RuntimeStatus.InstanceID across restarts.
func (m *Manager) Counters() []TrafficSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]TrafficSnapshot, 0, len(m.counters))
	for key, counter := range m.counters {
		result = append(result, TrafficSnapshot{key.inbound, key.user, counter.upload.Load(), counter.download.Load()})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Inbound != result[j].Inbound {
			return result[i].Inbound < result[j].Inbound
		}
		return result[i].User < result[j].User
	})
	return result
}
