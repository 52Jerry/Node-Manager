package userstate

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestCountersRemainSortedAndRetainRevokedUserTail(t *testing.T) {
	m := NewManager()
	table := m.NewTable()
	ids, publish := table.Prepare(map[string]string{"first": "password"}, nil)
	m.Commit(publish)
	server, peer := net.Pipe()
	defer peer.Close()
	ctx, session := m.NewSession(context.Background(), server)
	defer session.Close()
	if err := Bind(ctx, ids["first"]); err != nil {
		t.Fatal(err)
	}
	for _, item := range []TrafficSnapshot{{"b", "first", 3, 4}, {"a", "last", 5, 6}, {"a", "first", 7, 8}} {
		counter := m.counter(adapter.InboundContext{Inbound: item.Inbound, User: item.User})
		counter.upload.Add(item.Upload)
		counter.download.Add(item.Download)
	}
	tailCounter := m.counter(adapter.InboundContext{Inbound: "a", User: "first"})
	want := []TrafficSnapshot{{"a", "first", 7, 8}, {"a", "last", 5, 6}, {"b", "first", 3, 4}}
	if got := m.Counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("before revoke = %+v, want %+v", got, want)
	}
	_, publish = table.Prepare(nil, nil)
	if got := m.Commit(publish); got != 1 {
		t.Fatalf("revoked %d sessions, want 1", got)
	}
	if got := m.Counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("revoke discarded or changed cumulative traffic: %+v", got)
	}
	// Bytes already in flight can still arrive after revocation. Retain this tail.
	tailCounter.upload.Add(1)
	want[0].Upload++
	if got := m.Counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("late tail = %+v, want %+v", got, want)
	}
}

func TestConcurrentCounterCreationAndSnapshots(t *testing.T) {
	m := NewManager()
	var workers sync.WaitGroup
	for user := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			counter := m.counter(adapter.InboundContext{Inbound: "in", User: strconv.Itoa(user)})
			for range 100 {
				counter.upload.Add(1)
				counter.download.Add(2)
				rows := m.Counters()
				for i := 1; i < len(rows); i++ {
					if rows[i-1].User >= rows[i].User {
						t.Error("snapshot is not sorted or contains duplicate identities")
					}
				}
			}
		}()
	}
	workers.Wait()
	rows := m.Counters()
	if len(rows) != 8 {
		t.Fatalf("got %d counters, want 8", len(rows))
	}
	for user, row := range rows {
		if row.Inbound != "in" || row.User != strconv.Itoa(user) || row.Upload != 100 || row.Download != 200 {
			t.Fatalf("unexpected final counter: %+v", row)
		}
	}
}
