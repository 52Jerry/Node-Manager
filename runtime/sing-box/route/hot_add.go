package route

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
)

type ruleSnapshot struct {
	rules   []adapter.Rule
	leases  int
	retired []adapter.Rule
}

func (r *Router) currentRules() []adapter.Rule {
	if snapshot := r.addedRules.Load(); snapshot != nil {
		return snapshot.rules
	}
	return r.rules
}

// PrepareAddedRules reuses every existing rule object; only new rules are
// started. Publishing replaces an immutable slice and never closes old rules.
func (r *Router) PrepareAddedRules(options []option.Rule, previousIndexes []int) (commit func(), abort func(), err error) {
	previous := r.currentRules()
	next := make([]adapter.Rule, len(options))
	var added []adapter.Rule
	abort = func() {
		for _, rule := range added {
			_ = rule.Close()
		}
	}
	for index, option := range options {
		if previousIndexes[index] >= 0 {
			next[index] = previous[previousIndexes[index]]
			continue
		}
		rule, e := R.NewRule(r.ctx, r.logger, option, false)
		if e != nil {
			abort()
			return nil, nil, e
		}
		added = append(added, rule)
		if e = rule.Start(); e != nil {
			abort()
			return nil, nil, e
		}
		next[index] = rule
	}
	kept := make(map[adapter.Rule]bool, len(next))
	for _, rule := range next {
		kept[rule] = true
	}
	var retired []adapter.Rule
	for _, rule := range previous {
		if !kept[rule] {
			retired = append(retired, rule)
		}
	}
	return func() {
		r.rulesAccess.Lock()
		old := r.addedRules.Load()
		if old == nil {
			old = &ruleSnapshot{rules: r.rules}
		}
		old.retired = retired
		r.addedRules.Store(&ruleSnapshot{rules: next})
		if old.leases == 0 {
			for _, rule := range old.retired {
				_ = rule.Close()
			}
			old.retired = nil
		}
		r.rulesAccess.Unlock()
	}, abort, nil
}

func (r *Router) acquireRules() ([]adapter.Rule, func()) {
	r.rulesAccess.Lock()
	snapshot := r.addedRules.Load()
	if snapshot == nil {
		snapshot = &ruleSnapshot{rules: r.rules}
		r.addedRules.Store(snapshot)
	}
	snapshot.leases++
	r.rulesAccess.Unlock()
	return snapshot.rules, func() {
		r.rulesAccess.Lock()
		snapshot.leases--
		if snapshot.leases == 0 {
			for _, rule := range snapshot.retired {
				_ = rule.Close()
			}
			snapshot.retired = nil
		}
		r.rulesAccess.Unlock()
	}
}
