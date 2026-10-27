package box_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	singmux "github.com/sagernet/sing-mux"
	vmess "github.com/sagernet/sing-vmess"
	vless "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func udpEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:n], addr)
		}
	}()
	return M.ParseSocksaddr(conn.LocalAddr().String())
}
func (f *runtimeFixture) dialPacket(kind, name, key string, destination M.Socksaddr) (net.PacketConn, error) {
	if kind == "socks" {
		client := socks.NewClient(&N.DefaultDialer{Dialer: net.Dialer{Timeout: time.Second}}, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", f.ports[kind])), socks.Version5, name, key)
		return client.ListenPacket(context.Background(), destination)
	}
	protocol := kind
	if kind == "vless-mux" {
		protocol = "vless"
	}
	if kind == "vmess-mux" {
		protocol = "vmess"
	}
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports[protocol]), time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	if protocol == "vless" {
		client, err := vless.NewClient(key, "", logger.NOP())
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		if kind == "vless-mux" {
			return client.DialEarlyXUDPPacketConn(raw, destination)
		}
		return client.DialPacketConn(raw, destination)
	}
	client, err := vmess.NewClient(key, "aes-128-gcm", 0)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if kind == "vmess-mux" {
		return client.DialXUDPPacketConn(raw, destination)
	}
	return client.DialPacketConn(raw, destination)
}
func packetExchange(conn net.PacketConn, destination M.Socksaddr) error {
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	want := []byte("udp-session")
	if _, err := conn.WriteTo(want, destination.UDPAddr()); err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFrom(buffer)
	// VLESS DialPacketConn emits an empty initial datagram while sending its
	// protocol handshake; consume that echoed datagram before the test payload.
	for err == nil && n == 0 {
		n, _, err = conn.ReadFrom(buffer)
	}
	if err != nil {
		return err
	}
	if string(buffer[:n]) != string(want) {
		return fmt.Errorf("wrong datagram")
	}
	return nil
}
func TestUserReloadUDPAndNativeMuxRevocation(t *testing.T) {
	f := newRuntimeFixture(t)
	destination := udpEcho(t)
	keep := map[string]net.PacketConn{}
	change := map[string]net.PacketConn{}
	for _, kind := range []string{"vless", "vmess", "socks", "vless-mux", "vmess-mux"} {
		for name, connections := range map[string]map[string]net.PacketConn{"keep": keep, "change": change} {
			conn, err := f.dialPacket(kind, name, name+"-key", destination)
			if err != nil {
				t.Fatal(kind, err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err = packetExchange(conn, destination); err != nil {
				t.Fatal(kind, name, err)
			}
			connections[kind] = conn
		}
	}
	for _, v := range inbounds(f) {
		v.(map[string]any)["users"] = v.(map[string]any)["users"].([]any)[:1]
	}
	status := apply(t, f)
	if status.ClosedSessions != 5 {
		t.Fatal("UDP/mux sessions were not tracked", status)
	}
	for kind, conn := range keep {
		if err := packetExchange(conn, destination); err != nil {
			t.Fatal("unaffected UDP/mux interrupted", kind, err)
		}
	}
	for kind, conn := range change {
		if err := packetExchange(conn, destination); err == nil {
			t.Fatal("revoked UDP/mux still forwards", kind)
		}
	}
}

func TestUserReloadClosesIdleAuthenticatedMuxAndUDPAssociation(t *testing.T) {
	f := newRuntimeFixture(t, func(config map[string]any) {
		config["inbounds"].([]any)[0].(map[string]any)["multiplex"] = map[string]any{"enabled": true}
	})
	var rawConnections []net.Conn
	// Native VLESS mux authenticates without opening a single child stream.
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["vless"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	key := uuid.NewV5(uuid.Nil, "change-key")
	native := vless.NewConn(raw, [16]byte(key), vmess.CommandMux, M.Socksaddr{}, "")
	if _, err = native.Write(nil); err != nil {
		t.Fatal(err)
	}
	rawConnections = append(rawConnections, raw)
	// sing-mux enters its own handshake through a normal VLESS connection.
	raw2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["vless"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw2.Close() })
	client, _ := vless.NewClient("change-key", "", logger.NOP())
	if _, err = client.DialConn(raw2, singmux.Destination); err != nil {
		t.Fatal(err)
	}
	rawConnections = append(rawConnections, raw2)
	// A UDP association with no first datagram must still be indexed by user.
	control, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["socks"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = socks.ClientHandshake5(control, 3, M.ParseSocksaddr("127.0.0.1:0"), "change", "change-key"); err != nil {
		t.Fatal(err)
	}
	rawConnections = append(rawConnections, control)
	deadline := time.Now().Add(2 * time.Second)
	for f.instance.UserRuntimeStatus().ActiveSessions < 3 {
		if time.Now().After(deadline) {
			t.Fatal("idle authenticated parent not registered")
		}
		time.Sleep(time.Millisecond)
	}
	for _, v := range inbounds(f) {
		v.(map[string]any)["users"] = v.(map[string]any)["users"].([]any)[:1]
	}
	status := apply(t, f)
	if status.ClosedSessions != 3 {
		t.Fatal(status)
	}
	for i, raw := range rawConnections {
		_ = raw.SetReadDeadline(time.Now().Add(time.Second))
		if _, err = raw.Read(make([]byte, 1)); err == nil {
			t.Fatal("idle parent survived", i)
		}
	}
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func TestUserReloadVLESSVisionTLSKeepsOtherSession(t *testing.T) {
	certificate, key := testCertificate(t)
	f := newRuntimeFixture(t, func(config map[string]any) {
		row := config["inbounds"].([]any)[0].(map[string]any)
		row["tls"] = map[string]any{"enabled": true, "certificate": []any{certificate}, "key": []any{key}}
		for _, v := range row["users"].([]any) {
			v.(map[string]any)["flow"] = "xtls-rprx-vision"
		}
	})
	dial := func(name string) net.Conn {
		raw, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["vless"]), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		client, _ := vless.NewClient(name+"-key", "xtls-rprx-vision", logger.NOP())
		conn, err := client.DialConn(raw, f.destination)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err = exchange(conn); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	keep, change := dial("keep"), dial("change")
	row := inbounds(f)[0].(map[string]any)
	row["users"] = row["users"].([]any)[:1]
	apply(t, f)
	if err := exchange(keep); err != nil {
		t.Fatal("Vision connection interrupted", err)
	}
	if err := exchange(change); err == nil {
		t.Fatal("revoked Vision connection survived")
	}
}

type markerHandler struct{ marker byte }

func (h markerHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		if err := N.ReportConnHandshakeSuccess(conn, conn); err != nil {
			return
		}
		buffer := make([]byte, 1)
		for {
			if _, err := io.ReadFull(conn, buffer); err != nil {
				return
			}
			if _, err := conn.Write([]byte{h.marker}); err != nil {
				return
			}
		}
	}()
}
func (h markerHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected packet connection")
}
func markerSOCKS(t *testing.T, marker byte) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				err := socks.HandleConnectionEx(context.Background(), conn, bufio.NewReader(conn), nil, markerHandler{marker}, nil, 0, M.ParseSocksaddr(conn.RemoteAddr().String()), nil)
				if err != nil {
					_ = conn.Close()
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
func TestUserReloadReplacesActualUserOutboundWithoutInterruptingOtherUsers(t *testing.T) {
	f := newRuntimeFixture(t)
	keep := mustDial(t, f, "vless", "keep", "keep-key")
	change := mustDial(t, f, "socks", "change", "change-key")
	for i, marker := range []byte{'A', 'B'} {
		port := markerSOCKS(t, marker)
		f.config["outbounds"].([]any)[2] = map[string]any{"type": "socks", "tag": "change-out", "server": "127.0.0.1", "server_port": port}
		status := apply(t, f)
		if status.ClosedSessions != 1 {
			t.Fatal("outbound update did not revoke affected user", status)
		}
		if err := exchange(change); err == nil {
			t.Fatal("old outbound session survived replacement")
		}
		if err := exchange(keep); err != nil {
			t.Fatal("other user's stream interrupted", err)
		}
		var err error
		change, err = f.dial("socks", "change", "change-key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = change.Close() })
		_ = change.SetDeadline(time.Now().Add(time.Second))
		_, _ = change.Write([]byte{'?'})
		got := make([]byte, 1)
		if _, err = io.ReadFull(change, got); err != nil || got[0] != marker {
			t.Fatal("wrong actual upstream", i, got, err)
		}
		if len(f.instance.Outbound().Outbounds()) != 3 {
			t.Fatal("retired outbound retained")
		}
	}
	rule := f.config["route"].(map[string]any)["rules"].([]any)[1].(map[string]any)
	delete(rule, "outbound")
	rule["action"] = "reject"
	status := apply(t, f)
	if status.ClosedSessions != 1 {
		t.Fatal("policy change did not revoke existing session", status)
	}
	if err := exchange(keep); err != nil {
		t.Fatal(err)
	}
	denied, err := f.dial("socks", "change", "change-key")
	if err == nil {
		defer denied.Close()
		err = exchange(denied)
	}
	if err == nil {
		t.Fatal("disabled user's new request was allowed")
	}
}

type handshakeCapture struct {
	net.Conn
	bytes []byte
}

func (c *handshakeCapture) Write(data []byte) (int, error) {
	c.bytes = append(c.bytes, data...)
	return len(data), nil
}
func TestUserReloadPreservesVMessReplayFilter(t *testing.T) {
	f := newRuntimeFixture(t)
	capture := &handshakeCapture{}
	client, err := vmess.NewClient("keep-key", "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.DialConn(capture, f.destination); err != nil {
		t.Fatal(err)
	}
	send := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.ports["vmess"]))
		if err != nil {
			return nil, err
		}
		_ = raw.SetDeadline(time.Now().Add(time.Second))
		_, err = raw.Write(capture.bytes)
		return raw, err
	}
	original, err := send()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	deadline := time.Now().Add(time.Second)
	for f.instance.UserRuntimeStatus().ActiveSessions == 0 {
		if time.Now().After(deadline) {
			t.Fatal("VMess handshake was not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	for _, v := range inbounds(f) {
		row := v.(map[string]any)
		if row["type"] == "vmess" {
			row["users"].([]any)[1].(map[string]any)["uuid"] = "rotate-another-user"
		}
	}
	apply(t, f)
	replay, err := send()
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	if _, err = replay.Read(make([]byte, 1)); err == nil {
		t.Fatal("replayed handshake accepted")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("replay was not actively rejected", err)
	}
}

func TestUserReloadAddsUsersWithOwnOutbound(t *testing.T) {
	f := newRuntimeFixture(t)
	keepers := map[string]net.Conn{}
	for _, kind := range []string{"vless", "vmess", "socks"} {
		keepers[kind] = mustDial(t, f, kind, "keep", "keep-key")
	}
	upstream := markerSOCKS(t, 'C')
	for _, value := range inbounds(f) {
		row := value.(map[string]any)
		user := map[string]any{"name": "new", "uuid": "new-key"}
		if row["type"] == "socks" {
			user = map[string]any{"username": "new", "password": "new-key"}
		}
		row["users"] = append(row["users"].([]any), user)
	}
	f.config["outbounds"] = append(f.config["outbounds"].([]any), map[string]any{"type": "socks", "tag": "new-out", "server": "127.0.0.1", "server_port": upstream})
	route := f.config["route"].(map[string]any)
	route["rules"] = append([]any{map[string]any{"auth_user": []any{"new"}, "action": "route", "outbound": "new-out"}}, route["rules"].([]any)...)
	status := apply(t, f)
	if status.ClosedSessions != 0 {
		t.Fatal("adding another user revoked existing sessions", status)
	}
	for kind, keep := range keepers {
		if err := exchange(keep); err != nil {
			t.Fatal(kind, err)
		}
		conn, err := f.dial(kind, "new", "new-key")
		if err != nil {
			t.Fatal(kind, err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte{'?'})
		response := make([]byte, 1)
		if _, err = io.ReadFull(conn, response); err != nil || response[0] != 'C' {
			t.Fatal("new user routed incorrectly", kind, response, err)
		}
	}
}
