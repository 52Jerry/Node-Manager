package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"

	"github.com/gofrs/uuid/v5"
)

type closeTestTracker struct {
	metadata trafficontrol.TrackerMetadata
	reads    atomic.Int64
	closes   atomic.Int64
}

func (t *closeTestTracker) Metadata() *trafficontrol.TrackerMetadata {
	t.reads.Add(1)
	return &t.metadata
}

func (t *closeTestTracker) Close() error {
	t.closes.Add(1)
	return nil
}

func TestCloseConnectionUsesIndexAndPreservesResponse(t *testing.T) {
	for _, test := range []struct {
		name       string
		requestID  string
		targetType string
		wantClosed int64
	}{
		{"known", uuid.UUID{1}.String(), C.TypeSOCKS, 1},
		{"dns excluded", uuid.UUID{1}.String(), C.TypeDNS, 0},
		{"unknown", uuid.UUID{3}.String(), C.TypeSOCKS, 0},
		{"invalid", "invalid-id", C.TypeSOCKS, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := trafficontrol.NewManager()
			target := &closeTestTracker{metadata: trafficontrol.TrackerMetadata{ID: uuid.UUID{1}, OutboundType: test.targetType}}
			other := &closeTestTracker{metadata: trafficontrol.TrackerMetadata{ID: uuid.UUID{2}, OutboundType: C.TypeSOCKS}}
			manager.Join(target)
			manager.Join(other)
			target.reads.Store(0)
			other.reads.Store(0)
			response := httptest.NewRecorder()
			connectionRouter(context.Background(), nil, manager).ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/"+test.requestID, nil))
			if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
				t.Fatalf("response = %d %q, want 204 without a body", response.Code, response.Body.String())
			}
			if got := target.closes.Load(); got != test.wantClosed {
				t.Fatalf("target closed %d times, want %d", got, test.wantClosed)
			}
			if other.closes.Load() != 0 || other.reads.Load() != 0 {
				t.Fatal("single close inspected or closed an unrelated connection")
			}
		})
	}
}
