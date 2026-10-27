package box

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/userstate"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

var ErrRuntimeConflict = errors.New("running instance or revision changed")
var ErrUnsupportedUserUpdate = errors.New("change requires a separate topology publication")

type RuntimeStatus struct {
	ActiveSessions int    `json:"activeSessions"`
	InstanceID     string `json:"instanceId"`
	Revision       uint64 `json:"revision"`
	ContentHash    string `json:"contentHash"`
	ClosedSessions int    `json:"closedSessions"`
	CleanupPending bool   `json:"cleanupPending"`
}

type userUpdatePlan struct {
	inboundIndexes   []int
	outboundIndexes  []int
	removedOutbounds []string
	ruleIndexes      []int
	changedNames     map[string]bool
}

func namedRows(value any) (map[string]map[string]any, error) {
	list, ok := value.([]any)
	if value == nil {
		return map[string]map[string]any{}, nil
	}
	if !ok {
		return nil, fmt.Errorf("expected an array")
	}
	result := make(map[string]map[string]any, len(list))
	for _, value := range list {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected an object")
		}
		tag, _ := row["tag"].(string)
		if tag == "" || result[tag] != nil {
			return nil, fmt.Errorf("missing or duplicate tag")
		}
		result[tag] = row
	}
	return result, nil
}
func without(row map[string]any, keys ...string) map[string]any {
	result := make(map[string]any, len(row))
	for k, v := range row {
		result[k] = v
	}
	for _, k := range keys {
		delete(result, k)
	}
	return result
}
func userNames(row map[string]any) ([]string, bool) {
	var names []string
	switch value := row["auth_user"].(type) {
	case string:
		names = []string{value}
	case []any:
		for _, v := range value {
			s, ok := v.(string)
			if !ok {
				return nil, false
			}
			names = append(names, s)
		}
	}
	return names, len(names) > 0
}

// Dynamic rule changes are deliberately limited to resource-free user rules.
// Logical, inverted, rule-set and process rules retain their original ordering.
func dynamicRule(row map[string]any, known, blocked map[string]bool) bool {
	names, ok := userNames(row)
	if !ok {
		return false
	}
	matched := false
	for _, name := range names {
		if name == "" || blocked[name] {
			return false
		}
		matched = matched || known[name]
	}
	// Agents may retain historical aliases which are no longer installed. They
	// cannot match a live session. Require at least one managed identity and
	// forbid aliases owned by any unsupported inbound before accepting the rule.
	if !matched {
		return false
	}
	allowed := map[string]bool{"type": true, "auth_user": true, "action": true, "outbound": true, "inbound": true, "network": true, "source_ip_cidr": true, "ip_cidr": true, "source_port": true, "source_port_range": true, "port": true, "port_range": true, "domain": true, "domain_suffix": true, "domain_keyword": true, "domain_regex": true, "method": true, "no_drop": true}
	for key := range row {
		if !allowed[key] {
			return false
		}
	}
	if kind, exists := row["type"]; exists && kind != "default" && kind != "" {
		return false
	}
	if action, exists := row["action"]; exists && action != "route" && action != "reject" && action != "" {
		return false
	}
	return true
}
func validateUsers(row map[string]any) (map[string]bool, error) {
	names := make(map[string]bool)
	ids := make(map[uuid.UUID]bool)
	list, ok := row["users"].([]any)
	if row["users"] != nil && !ok {
		return nil, fmt.Errorf("invalid users array")
	}
	for _, value := range list {
		user, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid user")
		}
		name, _ := user["name"].(string)
		if row["type"] == "socks" {
			name, _ = user["username"].(string)
			password, _ := user["password"].(string)
			if password == "" || len(name) > 255 || len(password) > 255 {
				return nil, fmt.Errorf("invalid SOCKS credential length")
			}
		}
		if name == "" || names[name] {
			return nil, fmt.Errorf("missing or duplicate authentication name")
		}
		names[name] = true
		if row["type"] != "socks" {
			raw, _ := user["uuid"].(string)
			if raw == "" {
				return nil, fmt.Errorf("missing UUID")
			}
			id, err := uuid.FromString(raw)
			if err != nil {
				id = uuid.NewV5(uuid.Nil, raw)
			}
			if ids[id] {
				return nil, fmt.Errorf("duplicate canonical UUID")
			}
			ids[id] = true
		}
		if row["type"] == "vmess" {
			if alter, exists := user["alterId"]; exists && alter != float64(0) {
				return nil, fmt.Errorf("dynamic VMess requires AEAD users")
			}
		}
	}
	return names, nil
}
func references(value any, tags map[string]bool) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "outbound" || key == "detour" || key == "download_detour" {
				if tag, ok := item.(string); ok && tags[tag] {
					return true
				}
			}
			if references(item, tags) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if references(item, tags) {
				return true
			}
		}
	}
	return false
}

func planUserUpdate(before, after map[string]any) (*userUpdatePlan, error) {
	plan := &userUpdatePlan{changedNames: make(map[string]bool)}
	oldIn, err := namedRows(before["inbounds"])
	if err != nil {
		return nil, err
	}
	newIn, err := namedRows(after["inbounds"])
	if err != nil {
		return nil, err
	}
	if len(oldIn) != len(newIn) || !reflect.DeepEqual(without(before, "inbounds", "outbounds", "route"), without(after, "inbounds", "outbounds", "route")) {
		return nil, ErrUnsupportedUserUpdate
	}
	oldRoute, newRoute := nested(before, "route"), nested(after, "route")
	if !reflect.DeepEqual(without(oldRoute, "rules"), without(newRoute, "rules")) {
		return nil, ErrUnsupportedUserUpdate
	}
	known := make(map[string]bool)
	blocked := make(map[string]bool)
	for tag, old := range oldIn {
		next := newIn[tag]
		if next == nil {
			return nil, ErrUnsupportedUserUpdate
		}
		kind := old["type"]
		supported := kind == "vless" || kind == "vmess" || kind == "socks"
		if !supported {
			if !reflect.DeepEqual(old, next) {
				return nil, ErrUnsupportedUserUpdate
			}
			for _, v := range rows(old, "users") {
				if row, ok := v.(map[string]any); ok {
					for _, field := range []string{"name", "username"} {
						if name, ok := row[field].(string); ok {
							blocked[name] = true
						}
					}
				}
			}
			continue
		}
		oldBase, newBase := without(old, "users"), without(next, "users")
		if kind == "socks" {
			if old["require_auth"] == true && next["require_auth"] != true {
				return nil, fmt.Errorf("cannot disable required SOCKS authentication")
			}
			delete(oldBase, "require_auth")
			delete(newBase, "require_auth")
		}
		if !reflect.DeepEqual(oldBase, newBase) {
			return nil, ErrUnsupportedUserUpdate
		}
		// Preserve unchanged legacy/unnamed inbounds, but never dynamically modify them.
		oldNames, oldErr := validateUsers(old)
		newNames, newErr := validateUsers(next)
		if oldErr != nil || newErr != nil {
			if !reflect.DeepEqual(old, next) {
				return nil, fmt.Errorf("dynamic inbound requires valid named users")
			}
			for _, v := range rows(old, "users") {
				if row, ok := v.(map[string]any); ok {
					for _, field := range []string{"name", "username"} {
						if name, ok := row[field].(string); ok {
							blocked[name] = true
						}
					}
				}
			}
			continue
		}
		for name := range oldNames {
			known[name] = true
		}
		for name := range newNames {
			known[name] = true
		}
	}
	for name := range blocked {
		delete(known, name)
	}
	if _, explicit := oldRoute["final"]; !explicit {
		oldList, newList := rows(before, "outbounds"), rows(after, "outbounds")
		if len(oldList) > 0 && (len(newList) == 0 || oldList[0].(map[string]any)["tag"] != newList[0].(map[string]any)["tag"]) {
			return nil, ErrUnsupportedUserUpdate
		}
	}
	oldOut, err := namedRows(before["outbounds"])
	if err != nil {
		return nil, err
	}
	newOut, err := namedRows(after["outbounds"])
	if err != nil {
		return nil, err
	}
	changedOut := make(map[string]bool)
	for tag, old := range oldOut {
		if !reflect.DeepEqual(old, newOut[tag]) {
			changedOut[tag] = true
			plan.removedOutbounds = append(plan.removedOutbounds, tag)
		}
	}
	for index, v := range rows(after, "outbounds") {
		next := v.(map[string]any)
		tag := next["tag"].(string)
		if !reflect.DeepEqual(next, oldOut[tag]) {
			changedOut[tag] = true
			plan.outboundIndexes = append(plan.outboundIndexes, index)
		}
	}
	for tag := range changedOut {
		for _, row := range []map[string]any{oldOut[tag], newOut[tag]} {
			if row == nil {
				continue
			}
			if (row["type"] != "direct" && row["type"] != "socks") || row["detour"] != nil {
				return nil, fmt.Errorf("only independent direct/SOCKS user outbounds can change")
			}
		}
	}
	if references(without(before, "outbounds", "route"), changedOut) || references(without(oldRoute, "rules"), changedOut) {
		return nil, fmt.Errorf("outbound is referenced by global configuration")
	}
	for tag, row := range oldOut {
		if !changedOut[tag] && references(row, changedOut) {
			return nil, fmt.Errorf("outbound is referenced by another outbound")
		}
	}

	// Compare each user's ordered policy, including its position relative to static
	// rules. Removing B from a shared A/B rule must not revoke unchanged A.
	policies := func(list []any) (map[string][]any, []any, error) {
		byUser := make(map[string][]any)
		var fixed []any
		section := 0
		for _, v := range list {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("invalid rule")
			}
			if !dynamicRule(row, known, blocked) {
				if references(row, changedOut) {
					return nil, nil, fmt.Errorf("outbound is referenced by an unmanaged rule")
				}
				fixed = append(fixed, row)
				section++
				continue
			}
			names, _ := userNames(row)
			for _, name := range names {
				normalized := without(row, "auth_user")
				if tag, ok := row["outbound"].(string); ok {
					if newOut[tag] == nil && oldOut[tag] == nil {
						return nil, nil, fmt.Errorf("unknown user outbound")
					}
				}
				byUser[name] = append(byUser[name], []any{section, normalized})
			}
		}
		return byUser, fixed, nil
	}
	oldRules, newRules := rows(oldRoute, "rules"), rows(newRoute, "rules")
	oldPolicies, oldFixed, err := policies(oldRules)
	if err != nil {
		return nil, err
	}
	newPolicies, newFixed, err := policies(newRules)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(oldFixed, newFixed) {
		return nil, ErrUnsupportedUserUpdate
	}
	for name := range known {
		changed := !reflect.DeepEqual(oldPolicies[name], newPolicies[name])
		for _, policy := range [][]any{oldPolicies[name], newPolicies[name]} {
			for _, item := range policy {
				if references(item, changedOut) {
					changed = true
				}
			}
		}
		if changed {
			plan.changedNames[name] = true
		}
	}
	previousByHash := make(map[string][]int, len(oldRules))
	for index, rule := range oldRules {
		hash := userstate.Fingerprint(rule)
		previousByHash[hash] = append(previousByHash[hash], index)
	}
	for _, next := range newRules {
		previous := -1
		hash := userstate.Fingerprint(next)
		if matches := previousByHash[hash]; len(matches) > 0 {
			candidate := matches[0]
			if reflect.DeepEqual(oldRules[candidate], next) {
				previous = candidate
				previousByHash[hash] = matches[1:]
			}
		}
		if previous < 0 && !dynamicRule(next.(map[string]any), known, blocked) {
			return nil, ErrUnsupportedUserUpdate
		}
		if previous < 0 {
			if tag, ok := next.(map[string]any)["outbound"].(string); ok && newOut[tag] == nil {
				return nil, fmt.Errorf("user rule targets a missing outbound")
			}
		}
		plan.ruleIndexes = append(plan.ruleIndexes, previous)
	}

	// Removing a target still referenced by a retained rule must fail preparation.
	for _, v := range newRules {
		if tag, ok := v.(map[string]any)["outbound"].(string); ok && changedOut[tag] && newOut[tag] == nil {
			return nil, fmt.Errorf("removed outbound is still referenced")
		}
	}
	for index, v := range rows(after, "inbounds") {
		next := v.(map[string]any)
		old := oldIn[next["tag"].(string)]
		changed := !reflect.DeepEqual(old, next)
		for _, user := range rows(next, "users") {
			row := user.(map[string]any)
			name, _ := row["name"].(string)
			if next["type"] == "socks" {
				name, _ = row["username"].(string)
			}
			changed = changed || plan.changedNames[name]
		}
		if changed {
			if _, err := validateUsers(next); err != nil {
				return nil, err
			}
			plan.inboundIndexes = append(plan.inboundIndexes, index)
		}
	}
	return plan, nil
}

var instanceSequence atomic.Uint64

// Cached committed metadata keeps status polling off the configuration writer.
func (s *Box) statusLocked() RuntimeStatus {
	if view := s.runtimeView.Load(); view != nil {
		result := *view
		result.ActiveSessions = s.userState.SessionCount()
		return result
	}
	if s.runtimeInstance == "" {
		id, err := uuid.NewV4()
		if err == nil {
			s.runtimeInstance = id.String()
		} else {
			s.runtimeInstance = fmt.Sprintf("%d-%d", s.createdAt.UnixNano(), instanceSequence.Add(1))
		}
	}
	object, _ := configObject(s.reloadContext, &s.reloadOptions)
	return s.publishRuntimeStatusLocked(userstate.Fingerprint(object))
}
func (s *Box) publishRuntimeStatusLocked(hash string) RuntimeStatus {
	status := RuntimeStatus{InstanceID: s.runtimeInstance, Revision: s.runtimeRevision, ContentHash: hash}
	s.runtimeView.Store(&status)
	status.ActiveSessions = s.userState.SessionCount()
	return status
}
func (s *Box) UserRuntimeStatus() RuntimeStatus {
	if view := s.runtimeView.Load(); view != nil {
		result := *view
		result.ActiveSessions = s.userState.SessionCount()
		return result
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.statusLocked()
}

// ReloadUserRoutes atomically replaces only the user-scoped rules/outbounds.
// The same plan validator protects shared/default/topology state as ReloadUsers.
func (s *Box) ReloadUserRoutes(rules []option.Rule, outbounds []option.Outbound, expectedRevision *uint64, expectedInstance string) (RuntimeStatus, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	status := s.statusLocked()
	if expectedRevision == nil || expectedInstance != status.InstanceID || *expectedRevision != status.Revision {
		return status, ErrRuntimeConflict
	}
	object, err := configObject(s.reloadContext, &s.reloadOptions)
	if err != nil {
		return status, err
	}
	data, err := json.Marshal(object)
	if err != nil {
		return status, err
	}
	updated, err := singjson.UnmarshalExtendedContext[option.Options](s.reloadContext, data)
	if err != nil {
		return status, err
	}
	if updated.Route == nil {
		updated.Route = &option.RouteOptions{}
	}
	updated.Route.Rules, updated.Outbounds = rules, outbounds
	return s.reloadUsersLocked(updated, expectedRevision, expectedInstance)
}

// ReloadUsers owns its input and rejects topology changes before mutating state.
// expectedInstance/expectedRevision fence stale requests across both updates and restarts.
func (s *Box) ReloadUsers(updated option.Options, expectedRevision *uint64, expectedInstance string) (RuntimeStatus, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadUsersLocked(updated, expectedRevision, expectedInstance)
}
func (s *Box) reloadUsersLocked(updated option.Options, expectedRevision *uint64, expectedInstance string) (RuntimeStatus, error) {
	status := s.statusLocked()
	select {
	case <-s.done:
		return status, fmt.Errorf("instance is closed")
	default:
	}
	if expectedInstance != "" && expectedInstance != status.InstanceID {
		return status, ErrRuntimeConflict
	}
	after, err := configObject(s.reloadContext, &updated)
	if err != nil {
		return status, err
	}
	if userstate.Fingerprint(after) == status.ContentHash {
		return status, nil
	}
	if expectedRevision != nil && *expectedRevision != status.Revision {
		return status, ErrRuntimeConflict
	}
	before, err := configObject(s.reloadContext, &s.reloadOptions)
	if err != nil {
		return status, err
	}
	plan, err := planUserUpdate(before, after)
	if err != nil {
		return status, err
	}
	// Decode a private copy so later caller mutations cannot alter the accepted revision.
	data, err := json.Marshal(after)
	if err != nil {
		return status, err
	}
	updated, err = singjson.UnmarshalExtendedContext[option.Options](s.reloadContext, data)
	if err != nil {
		return status, err
	}
	var userCommits []func() []*userstate.Identity
	for _, index := range plan.inboundIndexes {
		options := updated.Inbounds[index]
		inbound, exists := s.inbound.Get(options.Tag)
		if !exists {
			return status, fmt.Errorf("dynamic inbound is unavailable")
		}
		preparer, ok := inbound.(interface {
			PrepareUserUpdate(any, map[string]bool) (func() []*userstate.Identity, error)
		})
		if !ok {
			return status, ErrUnsupportedUserUpdate
		}
		commit, e := preparer.PrepareUserUpdate(options.Options, plan.changedNames)
		if e != nil {
			return status, e
		}
		userCommits = append(userCommits, commit)
	}
	var ruleOptions []option.Rule
	if updated.Route != nil {
		ruleOptions = updated.Route.Rules
	}
	publishRules, abortRules, err := s.router.PrepareAddedRules(ruleOptions, plan.ruleIndexes)
	if err != nil {
		return status, err
	}
	var outboundOptions []option.Outbound
	for _, index := range plan.outboundIndexes {
		outboundOptions = append(outboundOptions, updated.Outbounds[index])
	}
	publishOutbounds, abortOutbounds, cleanupOutbounds, err := s.outbound.PrepareUserUpdate(s.reloadContext, s.router, s.logFactory, outboundOptions, plan.removedOutbounds)
	if err != nil {
		abortRules()
		return status, err
	}
	_ = abortOutbounds // All remaining publications are infallible and run under the admission gate.
	closed := s.userState.Commit(func() []*userstate.Identity {
		publishOutbounds()
		publishRules()
		var retired []*userstate.Identity
		for _, commit := range userCommits {
			retired = append(retired, commit()...)
		}
		return retired
	})
	s.reloadOptions = updated
	s.runtimeRevision++
	status = s.publishRuntimeStatusLocked(userstate.Fingerprint(after))
	status.ClosedSessions = closed
	if err = cleanupOutbounds(); err != nil {
		status.CleanupPending = true
		s.logger.Warn("user update committed; retired outbound cleanup failed")
	}
	return status, nil
}

func (s *Box) UserTrafficCounters() (string, []userstate.TrafficSnapshot) {
	return s.UserRuntimeStatus().InstanceID, s.userState.Counters()
}

// PreviewUserUpdate normalizes through this exact binary's option schema. Agents
// must not approximate omitempty/default/legacy field behavior in another language.
func (s *Box) PreviewUserUpdate(updated option.Options) (RuntimeStatus, string, bool, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	status := s.statusLocked()
	after, err := configObject(s.reloadContext, &updated)
	if err != nil {
		return status, "", false, err
	}
	hash := userstate.Fingerprint(after)
	if hash == status.ContentHash {
		return status, hash, true, nil
	}
	before, err := configObject(s.reloadContext, &s.reloadOptions)
	if err != nil {
		return status, "", false, err
	}
	_, planErr := planUserUpdate(before, after)
	return status, hash, planErr == nil, nil
}

// FenceUserRuntime is a CAS barrier for recovery after an ambiguous PUT timeout.
// A late PUT carrying the pre-fence revision can no longer change configuration.
func (s *Box) FenceUserRuntime(expectedRevision uint64, expectedInstance string) (RuntimeStatus, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	status := s.statusLocked()
	select {
	case <-s.done:
		return status, fmt.Errorf("instance is closed")
	default:
	}
	if expectedInstance != status.InstanceID || expectedRevision != status.Revision {
		return status, ErrRuntimeConflict
	}
	s.runtimeRevision++
	return s.publishRuntimeStatusLocked(status.ContentHash), nil
}
