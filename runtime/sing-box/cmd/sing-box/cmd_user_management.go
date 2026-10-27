package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

var managementSocket string
var allowDisruptiveReload bool

func init() {
	mainCommand.PersistentFlags().StringVar(&managementSocket, "management-socket", "", "private Unix socket for user runtime updates")
	mainCommand.PersistentFlags().BoolVar(&allowDisruptiveReload, "allow-disruptive-reload", false, "allow SIGHUP topology changes to close all connections")
}

func userManagementHandler(instance *box.Box) http.Handler {
	mux := http.NewServeMux()
	// Admit before decoding: the body limit alone does not bound aggregate heap.
	heavy := make(chan struct{}, 1)
	guarded := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case heavy <- struct{}{}:
				defer func() { <-heavy }()
			default:
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"runtime_busy"}`, http.StatusTooManyRequests)
				return
			}
			if r.Context().Err() != nil {
				return
			}
			next(w, r)
		}
	}
	write := func(w http.ResponseWriter, status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /management/v1/status", func(w http.ResponseWriter, r *http.Request) { write(w, http.StatusOK, instance.UserRuntimeStatus()) })
	mux.HandleFunc("GET /management/v1/counters", func(w http.ResponseWriter, r *http.Request) {
		id, counters := instance.UserTrafficCounters()
		write(w, http.StatusOK, map[string]any{"instanceId": id, "users": counters})
	})

	mux.HandleFunc("POST /management/v1/preview", guarded(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Config json.RawMessage `json:"config"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || len(request.Config) == 0 {
			write(w, 400, map[string]string{"error": "config_required"})
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			write(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		options, err := singjson.UnmarshalExtendedContext[option.Options](globalCtx, request.Config)
		if err != nil {
			write(w, 400, map[string]string{"error": "invalid_configuration"})
			return
		}
		status, hash, supported, err := instance.PreviewUserUpdate(options)
		if err != nil {
			write(w, 422, map[string]string{"error": "preview_rejected"})
			return
		}
		write(w, 200, map[string]any{"runtime": status, "contentHash": hash, "supported": supported})
	}))
	mux.HandleFunc("POST /management/v1/fence", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Instance string  `json:"expectedInstanceId"`
			Revision *uint64 `json:"expectedRevision"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.Instance == "" || request.Revision == nil {
			write(w, 400, map[string]string{"error": "runtime_fence_required"})
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			write(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		status, err := instance.FenceUserRuntime(*request.Revision, request.Instance)
		if err != nil {
			write(w, 409, map[string]any{"error": "runtime_revision_conflict", "runtime": status})
			return
		}
		write(w, 200, status)
	})
	configuration := guarded(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ExpectedInstanceID string          `json:"expectedInstanceId"`
			ExpectedRevision   *uint64         `json:"expectedRevision"`
			Config             json.RawMessage `json:"config"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.ExpectedRevision == nil || request.ExpectedInstanceID == "" || len(request.Config) == 0 {
			write(w, http.StatusBadRequest, map[string]string{"error": "expectedInstanceId, expectedRevision and config are required"})
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			write(w, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON object"})
			return
		}
		options, err := singjson.UnmarshalExtendedContext[option.Options](globalCtx, request.Config)
		if err != nil {
			write(w, http.StatusBadRequest, map[string]string{"error": "invalid sing-box configuration"})
			return
		}
		status, err := instance.ReloadUsers(options, request.ExpectedRevision, request.ExpectedInstanceID)
		if err != nil {
			code := http.StatusUnprocessableEntity
			category := "invalid_user_update"
			if errors.Is(err, box.ErrUnsupportedUserUpdate) {
				category = "unsupported_topology_change"
			}
			if errors.Is(err, box.ErrRuntimeConflict) {
				code = http.StatusConflict
				category = "runtime_revision_conflict"
			}
			// Configuration parsing errors may contain credentials; expose status and a
			// fixed error category rather than echoing configuration values.
			write(w, code, map[string]any{"error": category, "runtime": status})
			return
		}
		write(w, http.StatusOK, status)
	})
	mux.HandleFunc("PUT /management/v1/users", configuration)
	mux.HandleFunc("PUT /management/v1/configuration", configuration)
	mux.HandleFunc("PUT /management/v1/routes", guarded(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ExpectedInstanceID string          `json:"expectedInstanceId"`
			ExpectedRevision   *uint64         `json:"expectedRevision"`
			Rules              json.RawMessage `json:"rules"`
			Outbounds          json.RawMessage `json:"outbounds"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.ExpectedInstanceID == "" || request.ExpectedRevision == nil || len(request.Rules) == 0 || len(request.Outbounds) == 0 {
			write(w, 400, map[string]string{"error": "route_snapshot_and_fence_required"})
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			write(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		// Use the core's option registry for route/action/outbound decoding.
		data, _ := json.Marshal(map[string]any{"route": map[string]any{"rules": request.Rules}, "outbounds": request.Outbounds})
		options, err := singjson.UnmarshalExtendedContext[option.Options](globalCtx, data)
		if err != nil {
			write(w, 400, map[string]string{"error": "invalid_route_snapshot"})
			return
		}
		status, err := instance.ReloadUserRoutes(options.Route.Rules, options.Outbounds, request.ExpectedRevision, request.ExpectedInstanceID)
		if err != nil {
			code := 422
			category := "unsupported_route_update"
			if errors.Is(err, box.ErrRuntimeConflict) {
				code = 409
				category = "runtime_revision_conflict"
			}
			write(w, code, map[string]any{"error": category, "runtime": status})
			return
		}
		write(w, 200, status)
	}))
	return mux
}

func startUserManagement(instance *box.Box) (*http.Server, error) {
	if managementSocket == "" {
		return nil, nil
	}
	if !filepath.IsAbs(managementSocket) {
		return nil, fmt.Errorf("management socket path must be absolute")
	}
	// Never remove an existing path: it may belong to another running instance.
	listener, err := net.Listen("unix", managementSocket)
	if err != nil {
		return nil, fmt.Errorf("listen on management socket: %w", err)
	}
	if err = os.Chmod(managementSocket, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	server := &http.Server{Handler: userManagementHandler(instance), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = server.Serve(listener) }()
	return server, nil
}
