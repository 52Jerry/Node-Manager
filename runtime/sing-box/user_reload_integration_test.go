package box_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	vmess "github.com/sagernet/sing-vmess"
	vless "github.com/sagernet/sing-vmess/vless"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type runtimeFixture struct {
	ctx         context.Context
	instance    *box.Box
	config      map[string]any
	ports       map[string]int
	destination M.Socksaddr
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
func fixtureOptions(t *testing.T, ctx context.Context, config map[string]any) option.Options {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	return options
}
func newRuntimeFixture(t *testing.T, configure ...func(map[string]any)) *runtimeFixture {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	f := &runtimeFixture{ctx: include.Context(context.Background()), ports: map[string]int{}, destination: M.ParseSocksaddr(echo.Addr().String())}
	var inbounds []any
	for _, kind := range []string{"vless", "vmess", "socks"} {
		f.ports[kind] = freePort(t)
		users := []any{map[string]any{"name": "keep", "uuid": "keep-key"}, map[string]any{"name": "change", "uuid": "change-key"}}
		inbound := map[string]any{"type": kind, "tag": kind, "listen": "127.0.0.1", "listen_port": f.ports[kind], "users": users}
		if kind == "socks" {
			inbound["require_auth"] = true
			inbound["users"] = []any{map[string]any{"username": "keep", "password": "keep-key"}, map[string]any{"username": "change", "password": "change-key"}}
		}
		inbounds = append(inbounds, inbound)
	}
	f.config = map[string]any{"log": map[string]any{"disabled": true}, "inbounds": inbounds, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "direct", "tag": "keep-out"}, map[string]any{"type": "direct", "tag": "change-out"}}, "route": map[string]any{"final": "direct", "rules": []any{map[string]any{"auth_user": []any{"keep"}, "action": "route", "outbound": "keep-out"}, map[string]any{"auth_user": []any{"change"}, "action": "route", "outbound": "change-out"}}}}
	for _, configure := range configure {
		configure(f.config)
	}
	f.instance, err = box.New(box.Options{Context: f.ctx, Options: fixtureOptions(t, f.ctx, f.config)})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.instance.Close() })
	return f
}
func (f *runtimeFixture) dial(kind, name, key string) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports[kind]), time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	var conn net.Conn
	switch kind {
	case "vless":
		client, e := vless.NewClient(key, "", logger.NOP())
		if e != nil {
			err = e
			break
		}
		conn, err = client.DialConn(raw, f.destination)
	case "vmess":
		client, e := vmess.NewClient(key, "aes-128-gcm", 0)
		if e != nil {
			err = e
			break
		}
		conn, err = client.DialConn(raw, f.destination)
	case "socks":
		_ = raw.Close()
		client := socks.NewClient(&N.DefaultDialer{Dialer: net.Dialer{Timeout: time.Second}}, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", f.ports[kind])), socks.Version5, name, key)
		conn, err = client.DialContext(context.Background(), "tcp", f.destination)
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}
func exchange(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	want := []byte("continuous-user-session")
	if _, err := conn.Write(want); err != nil {
		return err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(want) {
		return fmt.Errorf("wrong data")
	}
	return nil
}
func mustDial(t *testing.T, f *runtimeFixture, kind, name, key string) net.Conn {
	t.Helper()
	conn, err := f.dial(kind, name, key)
	if err != nil {
		t.Fatal(kind, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err = exchange(conn); err != nil {
		t.Fatal(kind, err)
	}
	return conn
}
func apply(t *testing.T, f *runtimeFixture) box.RuntimeStatus {
	t.Helper()
	status, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return status
}
func inbounds(f *runtimeFixture) []any { return f.config["inbounds"].([]any) }

func TestUserReloadRotationReorderAndDeletionPreserveOtherUsers(t *testing.T) {
	f := newRuntimeFixture(t)
	keepers := map[string]net.Conn{}
	changed := map[string]net.Conn{}
	for _, kind := range []string{"vless", "vmess", "socks"} {
		keepers[kind] = mustDial(t, f, kind, "keep", "keep-key")
		changed[kind] = mustDial(t, f, kind, "change", "change-key")
	}
	initial := f.instance.UserRuntimeStatus()
	for _, value := range inbounds(f) {
		row := value.(map[string]any)
		user := row["users"].([]any)[1].(map[string]any)
		if row["type"] == "socks" {
			user["password"] = "rotated-key"
		} else {
			user["uuid"] = "rotated-key"
		}
	}
	status := apply(t, f)
	if status.ClosedSessions != 3 || status.InstanceID != initial.InstanceID {
		t.Fatalf("unexpected receipt %+v", status)
	}
	for kind, conn := range keepers {
		if err := exchange(conn); err != nil {
			t.Fatal("unchanged user disconnected", kind, err)
		}
	}
	for kind, conn := range changed {
		if err := exchange(conn); err == nil {
			t.Fatal("old connection survived rotation", kind)
		}
		old, err := f.dial(kind, "change", "change-key")
		if err == nil {
			err = exchange(old)
			_ = old.Close()
		}
		if err == nil {
			t.Fatal("old credentials accepted", kind)
		}
		changed[kind] = mustDial(t, f, kind, "change", "rotated-key")
	}
	for _, v := range inbounds(f) {
		users := v.(map[string]any)["users"].([]any)
		users[0], users[1] = users[1], users[0]
	}
	if status = apply(t, f); status.ClosedSessions != 0 {
		t.Fatal("reordering revoked users", status)
	}
	for _, connections := range []map[string]net.Conn{keepers, changed} {
		for kind, conn := range connections {
			if err := exchange(conn); err != nil {
				t.Fatal("reordering broke identity", kind, err)
			}
		}
	}
	for _, v := range inbounds(f) {
		row := v.(map[string]any)
		row["users"] = row["users"].([]any)[1:]
	}
	route := f.config["route"].(map[string]any)
	route["rules"] = route["rules"].([]any)[:1]
	f.config["outbounds"] = f.config["outbounds"].([]any)[:2]
	if status = apply(t, f); status.ClosedSessions != 3 {
		t.Fatal("deleted user not closed", status)
	}
	for kind, conn := range changed {
		if err := exchange(conn); err == nil {
			t.Fatal("deleted session survived", kind)
		}
	}
	for kind, conn := range keepers {
		if err := exchange(conn); err != nil {
			t.Fatal("deleting another user broke connection", kind, err)
		}
	}
}

func TestUserReloadFailureIsAtomicAndRetryIsIdempotent(t *testing.T) {
	f := newRuntimeFixture(t)
	conn := mustDial(t, f, "vmess", "keep", "keep-key")
	before := f.instance.UserRuntimeStatus()
	inbounds(f)[0].(map[string]any)["listen_port"] = freePort(t)
	if _, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), nil, ""); err == nil {
		t.Fatal("topology update accepted")
	}
	if got := f.instance.UserRuntimeStatus(); !reflect.DeepEqual(got, before) {
		t.Fatal("rejection changed running state", got)
	}
	if err := exchange(conn); err != nil {
		t.Fatal(err)
	}
	inbounds(f)[0].(map[string]any)["listen_port"] = f.ports["vless"]
	inbounds(f)[0].(map[string]any)["users"].([]any)[1].(map[string]any)["uuid"] = "changed"
	stale := uint64(999)
	if _, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), &stale, before.InstanceID); err != box.ErrRuntimeConflict {
		t.Fatal("stale revision accepted", err)
	}
	accepted, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), &before.Revision, before.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), &before.Revision, before.InstanceID)
	if err != nil || retry.Revision != accepted.Revision || retry.ClosedSessions != 0 {
		t.Fatal("retry not idempotent", retry, err)
	}
	// Force a resource-construction failure after credentials and rules prepare.
	inbounds(f)[0].(map[string]any)["users"].([]any)[1].(map[string]any)["uuid"] = "not-to-be-published"
	f.config["outbounds"].([]any)[2] = map[string]any{"type": "socks", "tag": "change-out", "version": "invalid-version", "server": "127.0.0.1", "server_port": 1234}
	if _, err := f.instance.ReloadUsers(fixtureOptions(t, f.ctx, f.config), nil, ""); err == nil {
		t.Fatal("invalid outbound accepted")
	}
	if got := f.instance.UserRuntimeStatus(); got.Revision != accepted.Revision || got.ContentHash != accepted.ContentHash {
		t.Fatal("partial update escaped", got)
	}
	if err := exchange(conn); err != nil {
		t.Fatal(err)
	}
}

func TestUserReloadEmptySOCKSDeniesAnonymousAccess(t *testing.T) {
	f := newRuntimeFixture(t)
	conn := mustDial(t, f, "socks", "change", "change-key")
	for _, v := range inbounds(f) {
		row := v.(map[string]any)
		if row["type"] == "socks" {
			row["users"] = []any{}
		}
	}
	apply(t, f)
	if err := exchange(conn); err == nil {
		t.Fatal("last SOCKS user remains connected")
	}
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["socks"]), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	_, _ = raw.Write([]byte{5, 1, 0})
	response := make([]byte, 2)
	if _, err = io.ReadFull(raw, response); err == nil && response[1] == 0 {
		t.Fatal("empty user table enabled anonymous proxy")
	}
	// Restart from the exact accepted configuration must also remain closed.
	_ = f.instance.Close()
	next, err := box.New(box.Options{Context: f.ctx, Options: fixtureOptions(t, f.ctx, f.config)})
	if err != nil {
		t.Fatal(err)
	}
	f.instance = next
	if err = next.Start(); err != nil {
		t.Fatal(err)
	}
	raw, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["socks"]), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	_, _ = raw.Write([]byte{5, 1, 0})
	if _, err = io.ReadFull(raw, response); err == nil && response[1] == 0 {
		t.Fatal("restart enabled anonymous proxy")
	}
}

func TestUserReloadRepeatedUpdatesKeepSessionAndBoundResources(t *testing.T) {
	f := newRuntimeFixture(t)
	conn := mustDial(t, f, "vmess", "keep", "keep-key")
	done := make(chan error, 1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
				if err := exchange(conn); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	for i := 0; i < 100; i++ {
		for _, v := range inbounds(f) {
			row := v.(map[string]any)
			user := row["users"].([]any)[1].(map[string]any)
			if row["type"] == "socks" {
				user["password"] = fmt.Sprint(i)
			} else {
				user["uuid"] = fmt.Sprint(i)
			}
		}
		apply(t, f)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal("continuous transfer interrupted", err)
	}
	if got := len(f.instance.Outbound().Outbounds()); got != 3 {
		t.Fatal("outbound objects accumulated", got)
	}
}

func TestUserTrafficCountersSurviveRevocationAndIncludeClosedSessions(t *testing.T) {
	f := newRuntimeFixture(t)
	conn := mustDial(t, f, "vmess", "change", "change-key")
	id, before := f.instance.UserTrafficCounters()
	var oldUpload, oldDownload int64
	for _, counter := range before {
		if counter.Inbound == "vmess" && counter.User == "change" {
			oldUpload = counter.Upload
			oldDownload = counter.Download
		}
	}
	if oldUpload == 0 || oldDownload == 0 {
		t.Fatal("user traffic not counted", before)
	}
	for _, value := range inbounds(f) {
		row := value.(map[string]any)
		row["users"] = row["users"].([]any)[:1]
	}
	apply(t, f)
	if err := exchange(conn); err == nil {
		t.Fatal("revoked connection survives")
	}
	nextID, after := f.instance.UserTrafficCounters()
	if nextID != id {
		t.Fatal("epoch changed on user update")
	}
	for _, counter := range after {
		if counter.Inbound == "vmess" && counter.User == "change" {
			if counter.Upload < oldUpload || counter.Download < oldDownload {
				t.Fatal("closed traffic lost", before, after)
			}
			return
		}
	}
	t.Fatal("closed user's counter disappeared", after)
}

func TestRuntimePreviewAndFenceBlockDelayedPublication(t *testing.T) {
	f := newRuntimeFixture(t)
	initial := f.instance.UserRuntimeStatus()
	for _, value := range inbounds(f) {
		row := value.(map[string]any)
		if row["type"] == "vmess" {
			row["users"].([]any)[1].(map[string]any)["uuid"] = "delayed-key"
		}
	}
	desired := fixtureOptions(t, f.ctx, f.config)
	status, hash, supported, err := f.instance.PreviewUserUpdate(desired)
	if err != nil || !supported || hash == initial.ContentHash || status.Revision != initial.Revision {
		t.Fatal("invalid preview", status, hash, supported, err)
	}
	if f.instance.UserRuntimeStatus().ContentHash != initial.ContentHash {
		t.Fatal("preview changed the running configuration")
	}
	fenced, err := f.instance.FenceUserRuntime(initial.Revision, initial.InstanceID)
	if err != nil || fenced.Revision <= initial.Revision || fenced.ContentHash != initial.ContentHash {
		t.Fatal("invalid fence", fenced, err)
	}
	if _, err = f.instance.ReloadUsers(desired, &initial.Revision, initial.InstanceID); err != box.ErrRuntimeConflict {
		t.Fatal("delayed pre-fence request applied", err)
	}
}
