package config

// MaxRuleSetCacheWeight is the weight limit of the memo of
// [MismatchRuleSets].
const MaxRuleSetCacheWeight = maxRuleSetCacheWeight

// RuleSetMisses returns the number of rule lists that a new memo of
// [MismatchRuleSets] compares when it gets each of the lists in order.
// The entries of the memo hold up to limit units of weight.
func RuleSetMisses(lists [][]ResolvedHTTPRule, limit int) int {
	m := newRuleSetMemo(limit)

	for _, rules := range lists {
		m.entry(rules).setsFor(rules)
	}

	return m.misses
}

// MemoRuleSets returns the sets of [MismatchRuleSets] for each of the
// lists, which a new memo of [MismatchRuleSets] gets in order.
func MemoRuleSets(lists [][]ResolvedHTTPRule) [][][]int {
	m := newRuleSetMemo(maxRuleSetCacheWeight)

	sets := make([][][]int, 0, len(lists))
	for _, rules := range lists {
		sets = append(sets, m.entry(rules).setsFor(rules))
	}

	return sets
}
