package box

import (
	"context"
	stdjson "encoding/json"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	singjson "github.com/sagernet/sing/common/json"
)

func configObject(ctx context.Context, value any) (map[string]any, error) {
	data, err := json.MarshalContext(ctx, value)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	err = stdjson.Unmarshal(data, &object)
	// auth.User has no JSON tags in sing v0.8.12. Normalize its exported field
	// names to the documented SOCKS config keys before comparing or hashing.
	for _, value := range rows(object, "inbounds") {
		inbound, ok := value.(map[string]any)
		if !ok || inbound["type"] != "socks" {
			continue
		}
		for _, value := range rows(inbound, "users") {
			user, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for upper, lower := range map[string]string{"Username": "username", "Password": "password"} {
				if value, exists := user[upper]; exists {
					user[lower] = value
					delete(user, upper)
				}
			}
		}
	}
	return object, err
}
func rows(object map[string]any, key string) []any { value, _ := object[key].([]any); return value }
func nested(object map[string]any, key string) map[string]any {
	value, _ := object[key].(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

// TryAdditiveReload is retained for callers of the original prototype.
// It now handles supported credential revocations and user policy updates too.
func (s *Box) TryAdditiveReload(updated option.Options) (bool, error) {
	_, err := s.ReloadUsers(updated, nil, "")
	return true, err
}

func cloneRuntimeOptions(ctx context.Context, options option.Options) (option.Options, error) {
	object, err := configObject(ctx, &options)
	if err != nil {
		return option.Options{}, err
	}
	data, err := stdjson.Marshal(object)
	if err != nil {
		return option.Options{}, err
	}
	return singjson.UnmarshalExtendedContext[option.Options](ctx, data)
}
