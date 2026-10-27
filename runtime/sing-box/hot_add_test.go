package box

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

const originalFixture = `{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"vless","listen_port":25111,"users":[{"name":"old","uuid":"a"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"auth_user":["old"],"outbound":"direct"},{"action":"reject"}],"final":"direct"}}`
const appendedFixture = `{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"vless","listen_port":25111,"users":[{"name":"old","uuid":"a"},{"name":"new","uuid":"b"}]}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"new-out","server":"127.0.0.1","server_port":25201}],"route":{"rules":[{"auth_user":["new"],"outbound":"new-out"},{"auth_user":["old"],"outbound":"direct"},{"action":"reject"}],"final":"direct"}}`

func fixtureObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(text), &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestContextMarshallingRetainsAuthenticationFields(t *testing.T) {
	options := option.Options{Inbounds: []option.Inbound{{Type: "vless", Tag: "vless", Options: &option.VLESSInboundOptions{Users: []option.VLESSUser{{Name: "fixture", UUID: "fixture-uuid", Flow: "xtls-rprx-vision"}}}}}}
	object, err := configObject(context.Background(), &options)
	if err != nil {
		t.Fatal(err)
	}
	user := rows(rows(object, "inbounds")[0].(map[string]any), "users")[0].(map[string]any)
	if user["uuid"] != "fixture-uuid" || user["flow"] != "xtls-rprx-vision" {
		t.Fatal("configuration comparison lost authentication options")
	}
}
