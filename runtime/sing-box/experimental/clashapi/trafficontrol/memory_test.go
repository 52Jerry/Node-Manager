package trafficontrol

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"

	"github.com/gofrs/uuid/v5"
)

func TestMemorySamplerRefreshesOncePerInterval(t *testing.T) {
	var sampler memorySampler
	now := time.Now()
	calls := 0
	sample := func() uint64 {
		calls++
		return uint64(calls)
	}
	for _, elapsed := range []time.Duration{0, time.Millisecond, memorySampleInterval - 1} {
		if got := sampler.load(now.Add(elapsed), sample); got != 1 {
			t.Fatalf("cached sample at %s = %d, want 1", elapsed, got)
		}
	}
	if got := sampler.load(now.Add(memorySampleInterval), sample); got != 2 {
		t.Fatalf("expired sample = %d, want 2", got)
	}
	if calls != 2 {
		t.Fatalf("sampled %d times, want 2", calls)
	}
}

func TestMemorySamplerConcurrentReadersShareSample(t *testing.T) {
	var sampler memorySampler
	var calls atomic.Int64
	now := time.Now()
	var readers sync.WaitGroup
	for range 64 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			if got := sampler.load(now, func() uint64 { calls.Add(1); return 42 }); got != 42 {
				t.Errorf("memory = %d, want 42", got)
			}
		}()
	}
	readers.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("sampled %d times for concurrent readers, want 1", got)
	}
}

type metadataTracker struct {
	metadata TrackerMetadata
	reads    atomic.Int64
}

func (t *metadataTracker) Metadata() *TrackerMetadata {
	t.reads.Add(1)
	return &t.metadata
}

func (*metadataTracker) Close() error { return nil }

func TestMemoryDoesNotEnumerateConnections(t *testing.T) {
	m := NewManager()
	tracker := &metadataTracker{metadata: TrackerMetadata{ID: uuid.UUID{1}}}
	m.connections.Store(tracker.metadata.ID, tracker)
	if got := m.Memory(); got == 0 {
		t.Fatal("process memory sample is empty")
	}
	if got := tracker.reads.Load(); got != 0 {
		t.Fatalf("memory read enumerated tracker metadata %d times", got)
	}
}

func TestSnapshotsKeepFreshConnectionsWithSharedMemory(t *testing.T) {
	m := NewManager()
	first := &metadataTracker{metadata: TrackerMetadata{ID: uuid.UUID{1}, OutboundType: C.TypeSOCKS}}
	second := &metadataTracker{metadata: TrackerMetadata{ID: uuid.UUID{2}, OutboundType: C.TypeSOCKS}}
	dns := &metadataTracker{metadata: TrackerMetadata{ID: uuid.UUID{3}, OutboundType: C.TypeDNS}}
	m.Join(first)
	m.Join(dns)
	m.PushUploaded(11)
	m.PushDownloaded(22)
	before := m.Snapshot()
	if len(before.Connections) != 1 || before.Connections[0] != first || before.Upload != 11 || before.Download != 22 {
		t.Fatalf("unexpected initial snapshot: %+v", before)
	}
	m.Join(second)
	m.Leave(first)
	after := m.Snapshot()
	if len(after.Connections) != 1 || after.Connections[0] != second {
		t.Fatal("memory caching retained a stale connection list")
	}
	if len(before.Connections) != 1 || before.Connections[0] != first {
		t.Fatal("later snapshot mutated the earlier connection slice")
	}
}
