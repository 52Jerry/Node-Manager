package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func TestManagementAPIRequiresFencesAndRejectsUnsupportedChanges(t *testing.T) {
	globalCtx = include.Context(context.Background())
	config := map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
	data, _ := json.Marshal(config)
	options, err := singjson.UnmarshalExtendedContext[option.Options](globalCtx, data)
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
	request := func(body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/management/v1/users", bytes.NewReader(data)))
		return recorder
	}
	if got := request(map[string]any{"config": config}); got.Code != http.StatusBadRequest {
		t.Fatal(got.Code, got.Body.String())
	}
	if got := request(map[string]any{"config": config, "expectedRevision": 0, "expectedInstanceId": "previous-process"}); got.Code != http.StatusConflict {
		t.Fatal(got.Code, got.Body.String())
	}
	if got := request(map[string]any{"config": config, "expectedRevision": 0, "expectedInstanceId": initial.InstanceID}); got.Code != http.StatusOK {
		t.Fatal(got.Code, got.Body.String())
	}
	for _, test := range []struct {
		path string
		body any
	}{
		{"/management/v1/preview", map[string]any{"config": config}},
		{"/management/v1/fence", map[string]any{"expectedInstanceId": initial.InstanceID, "expectedRevision": initial.Revision}},
	} {
		data, _ := json.Marshal(test.body)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(data)))
		if recorder.Code != 200 {
			t.Fatal(test.path, recorder.Code, recorder.Body.String())
		}
	}
	config["log"] = map[string]any{"disabled": false}
	if got := request(map[string]any{"config": config, "expectedRevision": instance.UserRuntimeStatus().Revision, "expectedInstanceId": initial.InstanceID}); got.Code != http.StatusUnprocessableEntity {
		t.Fatal(got.Code, got.Body.String())
	}
	if instance.UserRuntimeStatus().ContentHash != initial.ContentHash {
		t.Fatal("failed request mutated runtime")
	}
	for _, path := range []string{"/management/v1/status", "/management/v1/counters"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || !json.Valid(recorder.Body.Bytes()) {
			t.Fatal(path, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/management/v1/users", bytes.NewBufferString(`{"expectedInstanceId":"x","expectedRevision":0,"config":{}} {}`)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatal("trailing JSON accepted")
	}
}
