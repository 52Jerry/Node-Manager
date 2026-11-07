package trafficontrol

import (
	"runtime"
	"sync"
	"time"
)

const memorySampleInterval = time.Second

type memorySampler struct {
	access    sync.Mutex
	sampledAt time.Time
	value     uint64
}

func (s *memorySampler) load(now time.Time, sample func() uint64) uint64 {
	s.access.Lock()
	defer s.access.Unlock()
	if s.sampledAt.IsZero() || now.Sub(s.sampledAt) >= memorySampleInterval {
		s.value = sample()
		s.sampledAt = now
	}
	return s.value
}

// Memory shares a short-lived process-memory sample without enumerating connections.
func (m *Manager) Memory() uint64 {
	return m.memory.load(time.Now(), func() uint64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.StackInuse + stats.HeapInuse + stats.HeapIdle - stats.HeapReleased
	})
}
