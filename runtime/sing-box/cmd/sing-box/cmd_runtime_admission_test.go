package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

type heldBody struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *heldBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *heldBody) Close() error { return nil }

func TestAdmissionPrecedesBodyReadAndStatusDoesNotWaitForWriter(t *testing.T) {
	globalCtx = include.Context(context.Background())
	config := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	options, err := singjson.UnmarshalExtendedContext[option.Options](globalCtx, config)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: globalCtx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	handler := userManagementHandler(instance)
	initial := instance.UserRuntimeStatus()
	body := &heldBody{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/management/v1/configuration", body))
	}()
	<-body.entered
	other := &heldBody{entered: make(chan struct{}), release: make(chan struct{})}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/management/v1/routes", other))
	if response.Code != 429 {
		t.Fatal(response.Code)
	}
	select {
	case <-other.entered:
		t.Fatal("overload body was decoded")
	default:
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/management/v1/status", nil))
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit")
	}
	data, _ := json.Marshal(map[string]any{"expectedInstanceId": initial.InstanceID, "expectedRevision": initial.Revision, "rules": []any{}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/management/v1/routes", bytes.NewReader(data)))
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	data, _ = json.Marshal(map[string]any{"expectedInstanceId": initial.InstanceID, "expectedRevision": instance.UserRuntimeStatus().Revision, "config": json.RawMessage(config)})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/management/v1/configuration", bytes.NewReader(data)))
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
}
