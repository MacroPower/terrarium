package firewall_test

import "github.com/google/nftables"

// ruleRecorder implements [firewall.Conn] for tests. It records all
// AddTable/AddChain/AddRule/AddSet/DelTable calls so tests can verify
// the rule structure without a real kernel.
type ruleRecorder struct {
	tables  []*nftables.Table
	chains  []*nftables.Chain
	rules   []*nftables.Rule
	sets    []*nftables.Set
	deleted []*nftables.Table
	nextID  uint32
}

func (r *ruleRecorder) AddTable(t *nftables.Table) *nftables.Table {
	r.tables = append(r.tables, t)
	return t
}

func (r *ruleRecorder) AddChain(c *nftables.Chain) *nftables.Chain {
	r.chains = append(r.chains, c)
	return c
}

func (r *ruleRecorder) AddRule(rule *nftables.Rule) *nftables.Rule {
	r.rules = append(r.rules, rule)
	return rule
}

func (r *ruleRecorder) AddSet(s *nftables.Set, _ []nftables.SetElement) error {
	r.nextID++
	s.ID = r.nextID
	r.sets = append(r.sets, s)

	return nil
}

func (r *ruleRecorder) DelTable(t *nftables.Table) {
	r.deleted = append(r.deleted, t)
}

func (r *ruleRecorder) Flush() error {
	return nil
}

func (r *ruleRecorder) chainNames() []string {
	var names []string
	for _, c := range r.chains {
		names = append(names, c.Name)
	}

	return names
}

func (r *ruleRecorder) rulesForChain(name string) []*nftables.Rule {
	var chain *nftables.Chain
	for _, c := range r.chains {
		if c.Name == name {
			chain = c
			break
		}
	}

	if chain == nil {
		return nil
	}

	var result []*nftables.Rule

	for _, rule := range r.rules {
		if rule.Chain == chain {
			result = append(result, rule)
		}
	}

	return result
}

func (r *ruleRecorder) setNames() []string {
	var names []string
	for _, s := range r.sets {
		names = append(names, s.Name)
	}

	return names
}
