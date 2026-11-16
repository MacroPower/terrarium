package config

import (
	"context"
	"fmt"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// maxMismatchRuleSet is the maximum number of HTTP rules with a
// mismatch action that one request can match, see [MismatchRuleSets].
// The number of rule sets doubles with each of these rules.
const maxMismatchRuleSet = 4

// maxMismatchSharedRoutes is the maximum number of route combinations
// for the sets of two or more HTTP rules of one Envoy virtual host, see
// [MismatchRuleSets]. A set gets one combination for each combination
// of its headerMatches that [combinesMismatchRoutes] reports, so a set
// with n of these headerMatches counts 2^n. The limit allows 4 sets
// that each reach [maxMismatchCombinedHeaders].
const maxMismatchSharedRoutes = 4 << maxMismatchCombinedHeaders

// MismatchActions returns the HeaderMatches entries of the rule whose
// Mismatch action logs or changes a request that mismatches, in the
// order of the rule. [MismatchLOG] logs the request, and [MismatchADD],
// [MismatchREPLACE], and [MismatchDELETE] with a Value change it. The
// result is nil for a rule that only allows or denies requests.
func (r ResolvedHTTPRule) MismatchActions() []HeaderMatch {
	var actions []HeaderMatch

	for _, hm := range r.HeaderMatches {
		if hm.Mismatch == MismatchLOG || changesHeader(hm) {
			actions = append(actions, hm)
		}
	}

	return actions
}

// MismatchRuleSets returns the sets of rules whose mismatch actions one
// request can get together. The rules are the HTTP rules of one Envoy
// virtual host, as one [ResolvedRule] holds them. Each set holds the
// indexes of its rules in ascending order, and each rule of a set has a
// mismatch action, see [ResolvedHTTPRule.MismatchActions].
//
// Cilium applies the mismatch actions of every HTTP rule that a request
// matches. A set therefore stands for the requests that match all of
// its rules. The result holds one set for each rule with a mismatch
// action. It also holds one set for each larger combination of these
// rules that one request can match. The larger sets come first. Take
// the first set of which a request matches every rule. The request
// matches no other rule with a mismatch action.
//
// Two rules go into one set unless their matchers prove that no
// request matches both. The proof holds when the Path, the Method, or
// the Host patterns of the two rules match no common text. For example,
// the paths "/v[12]/a/.*" and "/v[12]/b/.*" share no request, but the
// paths "/(a|b)/.*" and "/b/.*" share "/b/x". The proof also holds when
// the two rules require different values of one header, and no rule
// changes that header.
//
// An Envoy route matches one path pattern. The rules of a set therefore
// have one Path, or no Path. Two rules that can match one request and
// have different paths never go into one set, and [Config.Validate]
// rejects them.
//
// The result depends only on the rules and their order. The function
// keeps the results for the rule lists of its recent calls, and the
// checks of [Config.Validate] share them. The rule list of one domain
// on many ports, or of many domains, therefore costs one comparison of
// its rules.
func MismatchRuleSets(rules []ResolvedHTTPRule) [][]int {
	var result [][]int

	for _, set := range ruleSetCache.entry(rules).setsFor(rules) {
		result = append(result, slices.Clone(set))
	}

	return result
}

// maxRuleSetCacheWeight is the maximum weight of the entries of
// [ruleSetCache], see [ruleSetEntryWeight].
const maxRuleSetCacheWeight = 1 << 24

// ruleSetCache holds the comparisons of the rule lists that
// [MismatchRuleSets] and [Config.Validate] got last.
var ruleSetCache = newRuleSetMemo(maxRuleSetCacheWeight)

// ruleSetMemo keeps the [ruleOverlaps] and the sets of
// [MismatchRuleSets] of each rule list that it got, keyed by
// [httpRulesKey]. Create instances with [newRuleSetMemo].
//
// The entries hold up to limit units of weight, see
// [ruleSetEntryWeight]. A new entry that does not fit removes every
// other entry, so the memo always keeps the entry of its last call.
type ruleSetMemo struct {
	entries map[string]*ruleSetEntry
	weight  int
	limit   int
	misses  int
	mu      sync.Mutex
}

// newRuleSetMemo creates a new [ruleSetMemo] whose entries hold up to
// limit units of weight.
func newRuleSetMemo(limit int) *ruleSetMemo {
	return &ruleSetMemo{entries: make(map[string]*ruleSetEntry), limit: limit}
}

// ruleSetEntry holds the results for one rule list. Each result is
// computed at its first use. Concurrent callers wait for that
// computation, so each result is computed once.
type ruleSetEntry struct {
	overlaps     ruleOverlaps
	sets         [][]int
	overlapsOnce sync.Once
	setsOnce     sync.Once
}

// entry returns the entry of the rules, and creates it when the memo
// does not hold it.
func (m *ruleSetMemo) entry(rules []ResolvedHTTPRule) *ruleSetEntry {
	key := httpRulesKey(rules)

	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[key]
	if ok {
		return e
	}

	weight := ruleSetEntryWeight(key, len(rules))
	if m.weight+weight > m.limit {
		clear(m.entries)

		m.weight = 0
	}

	e = &ruleSetEntry{}
	m.entries[key] = e
	m.weight += weight
	m.misses++

	return e
}

// ruleSetEntryWeight returns the weight of the entry for a rule list
// with the key and n rules. It counts the bytes of the key, and the
// bytes that the [ruleOverlaps] of n rules hold at most.
func ruleSetEntryWeight(key string, n int) int {
	return len(key) + n*(n-1)/2 + 16*n
}

// overlapsFor returns the [ruleOverlaps] of the rules, which must
// have the key of the entry.
func (e *ruleSetEntry) overlapsFor(rules []ResolvedHTTPRule) ruleOverlaps {
	e.overlapsOnce.Do(func() {
		e.overlaps = newRuleOverlaps(rules)
	})

	return e.overlaps
}

// setsFor returns the sets of [MismatchRuleSets] for the rules, which
// must have the key of the entry. The caller must not change the
// result.
func (e *ruleSetEntry) setsFor(rules []ResolvedHTTPRule) [][]int {
	overlaps := e.overlapsFor(rules)

	e.setsOnce.Do(func() {
		walkMismatchRuleSets(rules, overlaps, func(set []int) bool {
			e.sets = append(e.sets, set)

			return true
		})

		slices.SortStableFunc(e.sets, func(a, b []int) int {
			return len(b) - len(a)
		})
	})

	return e.sets
}

// httpRulesKey returns a key that differs for two rule lists with
// different results of [MismatchRuleSets] or [validateMismatchRules].
// Two rule lists get the same key only when they hold the same rules in
// the same order. The key holds each field of each rule in order. It
// puts the length of each string and of each list before its content,
// so the bytes of one field never read as another field.
func httpRulesKey(rules []ResolvedHTTPRule) string {
	var b strings.Builder

	writeString := func(s string) {
		fmt.Fprintf(&b, "%d:%s", len(s), s)
	}

	fmt.Fprintf(&b, "%d;", len(rules))

	for _, hr := range rules {
		writeString(hr.Method)
		writeString(hr.Path)
		writeString(hr.Host)

		fmt.Fprintf(&b, "%d;", len(hr.Headers))

		for _, h := range hr.Headers {
			writeString(h)
		}

		fmt.Fprintf(&b, "%d;", len(hr.HeaderMatches))

		for _, hm := range hr.HeaderMatches {
			writeString(hm.Name)
			writeString(hm.Value)
			writeString(string(hm.Mismatch))
		}
	}

	return b.String()
}

// walkMismatchRuleSets calls visit for each set of [MismatchRuleSets],
// and for each set before the sets that add a rule to it. It stops when
// visit returns false. The visit function must not change its argument.
// The overlaps hold the result of [newRuleOverlaps] for the rules.
func walkMismatchRuleSets(rules []ResolvedHTTPRule, overlaps ruleOverlaps, visit func(set []int) bool) {
	candidates := overlaps.candidates

	var extend func(set []int, from int) bool

	extend = func(set []int, from int) bool {
		for k := from; k < len(candidates); k++ {
			i := candidates[k]

			shared := !slices.ContainsFunc(set, func(j int) bool {
				return overlaps.disjoint(i, j) || !pathsCombine(rules[i], rules[j])
			})
			if !shared {
				continue
			}

			grown := append(slices.Clone(set), i)
			if !visit(grown) || !extend(grown, k+1) {
				return false
			}
		}

		return true
	}

	extend(nil, 0)
}

// pathsCombine reports whether one Envoy route can match the paths of
// both rules. A route has one path pattern, so the two rules must have
// the same Path, or one of them must have no Path.
func pathsCombine(a, b ResolvedHTTPRule) bool {
	return a.Path == "" || b.Path == "" || a.Path == b.Path
}

// maxIntersectWork is the work that [newRuleOverlaps] spends on the
// patterns of one rule list, see [intersectBudget]. The two rules of
// each pair that it reaches after the work runs out count as rules
// that can match one request, unless their header values prove
// otherwise.
const maxIntersectWork = 1 << 22

// ruleOverlaps records which of the HTTP rules with a mismatch action
// can match one request. Create instances with [newRuleOverlaps].
type ruleOverlaps struct {
	// The indexes of the rules that have a mismatch action, in
	// ascending order.
	candidates []int
	// The position in candidates of each rule, or -1 for a rule
	// without a mismatch action.
	position []int
	// One entry for each two candidates, see [ruleOverlaps.disjoint].
	apart []bool
}

// newRuleOverlaps creates a new [ruleOverlaps] for the rules. It
// compares each two rules with a mismatch action, see
// [ruleMatchers.disjoint]. The comparisons share one
// [intersectBudget] of [maxIntersectWork], and they run in the order
// of the rules, so one rule list always gives the same result.
func newRuleOverlaps(rules []ResolvedHTTPRule) ruleOverlaps {
	matchers, candidates := newRuleMatchers(rules)

	position := make([]int, len(rules))
	for i := range position {
		position[i] = -1
	}

	for n, i := range candidates {
		position[i] = n
	}

	budget := intersectBudget{left: maxIntersectWork}
	apart := make([]bool, len(candidates)*(len(candidates)-1)/2)

	for m := range candidates {
		for n := range m {
			apart[m*(m-1)/2+n] = matchers[candidates[n]].disjoint(matchers[candidates[m]], &budget)
		}
	}

	return ruleOverlaps{candidates: candidates, position: position, apart: apart}
}

// disjoint reports whether [ruleMatchers.disjoint] proved that no
// request matches both of the rules at the indexes i and j. Both rules
// must have a mismatch action, and i must differ from j.
func (o ruleOverlaps) disjoint(i, j int) bool {
	n, m := o.position[i], o.position[j]
	if n > m {
		n, m = m, n
	}

	return o.apart[m*(m-1)/2+n]
}

// ruleMatchers holds the matchers of one [ResolvedHTTPRule] that can
// prove that no request matches both of two rules, see
// [ruleMatchers.disjoint].
type ruleMatchers struct {
	// The Path, the Method, and the Host pattern of the rule, see
	// [compileFullMatch]. A nil pattern matches every text.
	path, method, host *fullMatch
	// The HeaderMatches entries of the rule that compare a header value
	// to deny a request, for the headers that no rule changes.
	values []HeaderMatch
}

// newRuleMatchers returns the [ruleMatchers] of the rules that have a
// mismatch action, at the index of each such rule. The first result
// holds the zero value at the index of every other rule. The second
// result holds the indexes of the rules that have a mismatch action.
func newRuleMatchers(rules []ResolvedHTTPRule) ([]ruleMatchers, []int) {
	changed := make(map[string]bool)

	for _, r := range rules {
		for _, hm := range r.HeaderMatches {
			if changesHeader(hm) {
				changed[strings.ToLower(hm.Name)] = true
			}
		}
	}

	var (
		candidates []int
		matchers   = make([]ruleMatchers, len(rules))
	)

	for i, r := range rules {
		if len(r.MismatchActions()) == 0 {
			continue
		}

		candidates = append(candidates, i)

		m := ruleMatchers{
			path:   compileFullMatch(r.Path),
			method: compileFullMatch(r.Method),
		}

		// The Envoy route matches the Host pattern without its "^" at
		// the start and its "$" at the end. It accepts a port after the
		// host, see the buildHostHeaderMatcher function of the envoy
		// package.
		if r.Host != "" {
			host := strings.TrimRight(strings.TrimLeft(r.Host, "^"), "$")
			m.host = compileFullMatch("^" + host + `(:[0-9]+)?$`)
		}

		for _, hm := range r.HeaderMatches {
			if hm.Mismatch == "" && hm.Value != "" && !changed[strings.ToLower(hm.Name)] {
				m.values = append(m.values, hm)
			}
		}

		matchers[i] = m
	}

	return matchers, candidates
}

// disjoint reports whether no request can match both rules. The result
// is false when the matchers do not prove it.
//
// The proof holds when the two rules require different values of one
// header, and no rule changes that header. Each of those values must
// equal the whole value of the header, so a request can hold at most
// one of them. The proof also holds when the Method, the Host, or the
// Path patterns of the two rules match no common text. The literal
// prefixes of the patterns prove that first, see [prefixesDisjoint].
// When they do not, [patternsIntersect] compares the patterns, and it
// spends work from budget.
//
// A mismatch action cannot change the path, the method, or the host of
// a request, see [ErrHeaderMatchMismatchReservedHeader]. The result
// therefore also holds for a request that another rule changed.
func (m ruleMatchers) disjoint(other ruleMatchers, budget *intersectBudget) bool {
	differentValues := slices.ContainsFunc(m.values, func(hm HeaderMatch) bool {
		return slices.ContainsFunc(other.values, func(o HeaderMatch) bool {
			return strings.EqualFold(hm.Name, o.Name) && hm.Value != o.Value
		})
	})

	return differentValues ||
		prefixesDisjoint(m.method, other.method) ||
		prefixesDisjoint(m.host, other.host) ||
		prefixesDisjoint(m.path, other.path) ||
		!patternsIntersect(m.method, other.method, budget) ||
		!patternsIntersect(m.host, other.host, budget) ||
		!patternsIntersect(m.path, other.path, budget)
}

// intersectBudget holds the work that [patternsIntersect] can still
// spend. One unit of work visits one state of a program, or one pair
// of states of two programs.
type intersectBudget struct {
	left int
}

// spend takes n units of work from the budget. It reports false, and
// it empties the budget, when the budget holds fewer than n units.
func (b *intersectBudget) spend(n int) bool {
	if n > b.left {
		b.left = 0

		return false
	}

	b.left -= n

	return true
}

// fullMatch holds a compiled pattern that must match a whole text. It
// keeps the states of [fullMatch.consumingStates] for each state that
// a walk reached. Create instances with [compileFullMatch].
type fullMatch struct {
	prog     *syntax.Prog
	prefix   string
	states   [][]int
	done     []bool
	mark     []int
	stamp    int
	complete bool
}

// compileFullMatch creates a new [fullMatch] for pattern with the
// syntax of [regexp.Compile]. The result matches the texts that
// pattern matches in full. It is nil for an empty pattern, which stands
// for a rule field that is not set, and for a pattern that does not
// compile. A nil result matches every text.
func compileFullMatch(pattern string) *fullMatch {
	if pattern == "" {
		return nil
	}

	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}

	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil
	}

	prefix, complete := prog.Prefix()

	return &fullMatch{
		prog:     prog,
		prefix:   prefix,
		complete: complete,
		states:   make([][]int, len(prog.Inst)),
		done:     make([]bool, len(prog.Inst)),
		mark:     make([]int, len(prog.Inst)),
	}
}

// prefixesDisjoint reports whether the literal prefixes of the two
// patterns prove that no text matches both patterns in full. It spends
// no work, so a rule list of many literal paths does not use up the
// work of [newRuleOverlaps]. A nil pattern matches every text.
//
// Every text of a pattern starts with its prefix. A pattern whose
// prefix is complete matches its prefix and no other text. Two
// patterns share no text when neither prefix starts with the other. A
// complete prefix also shares no text with a longer prefix. A pattern
// that ignores case, or that starts with an empty-width assertion, has
// an empty prefix, which proves nothing.
func prefixesDisjoint(a, b *fullMatch) bool {
	if a == nil || b == nil {
		return false
	}

	switch {
	case a.complete && b.complete:
		return a.prefix != b.prefix
	case a.complete:
		return !strings.HasPrefix(a.prefix, b.prefix)
	case b.complete:
		return !strings.HasPrefix(b.prefix, a.prefix)
	default:
		return !strings.HasPrefix(a.prefix, b.prefix) && !strings.HasPrefix(b.prefix, a.prefix)
	}
}

// maxIntersectStates is the maximum number of pairs of states of two
// programs that [patternsIntersect] compares. Two patterns whose
// programs have more pairs count as patterns that share a text.
const maxIntersectStates = 1 << 20

// patternsIntersect reports whether one text matches both patterns in
// full. A nil pattern matches every text. The result is true when the
// test cannot prove that no such text exists. That includes two
// patterns whose programs have more than [maxIntersectStates] pairs of
// states, and a test that needs more work than budget holds.
//
// The test walks the pairs of states of the two programs that one text
// can reach. A pair advances on a rune that both programs accept at
// their states. The programs share a text when a pair reaches the
// match state of both. The test treats every empty-width assertion,
// such as "^", "$", and `\b`, as passed. A text that it finds might
// therefore fail such an assertion, but the test never misses a text
// that both patterns match.
func patternsIntersect(a, b *fullMatch, budget *intersectBudget) bool {
	if a == nil || b == nil {
		return true
	}

	pairs := len(a.prog.Inst) * len(b.prog.Inst)
	if pairs > maxIntersectStates || !budget.spend(pairs/64+1) {
		return true
	}

	var (
		width = len(b.prog.Inst)
		seen  = make([]uint64, pairs/64+1)
		queue [][2]int
	)

	push := func(pcA, pcB int) bool {
		statesA, ok := a.consumingStates(pcA, budget)
		if !ok {
			return false
		}

		statesB, ok := b.consumingStates(pcB, budget)
		if !ok || !budget.spend(len(statesA)*len(statesB)) {
			return false
		}

		for _, x := range statesA {
			for _, y := range statesB {
				k := x*width + y
				if seen[k/64]&(1<<(k%64)) != 0 {
					continue
				}

				seen[k/64] |= 1 << (k % 64)

				queue = append(queue, [2]int{x, y})
			}
		}

		return true
	}

	if !push(a.prog.Start, b.prog.Start) {
		return true
	}

	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]

		instA, instB := &a.prog.Inst[p[0]], &b.prog.Inst[p[1]]

		switch {
		case instA.Op == syntax.InstMatch && instB.Op == syntax.InstMatch:
			return true
		case instA.Op == syntax.InstMatch || instB.Op == syntax.InstMatch:
			continue
		case runeRangesIntersect(instRuneRanges(instA), instRuneRanges(instB)):
			if !push(int(instA.Out), int(instB.Out)) {
				return true
			}
		}
	}

	return false
}

// consumingStates returns the states of the program that consume a
// rune or match, and that the state pc reaches without consuming a
// rune. It keeps each result for the next call with the same pc. It
// spends one unit of budget for each state that it visits, and it
// reports false when the budget runs out.
func (f *fullMatch) consumingStates(pc int, budget *intersectBudget) ([]int, bool) {
	if f.done[pc] {
		return f.states[pc], true
	}

	f.stamp++

	var (
		states []int
		stack  = []int{pc}
	)

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if f.mark[s] == f.stamp {
			continue
		}

		if !budget.spend(1) {
			return nil, false
		}

		f.mark[s] = f.stamp
		inst := &f.prog.Inst[s]

		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, int(inst.Out), int(inst.Arg))
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			stack = append(stack, int(inst.Out))
		case syntax.InstMatch, syntax.InstRune, syntax.InstRune1,
			syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			states = append(states, s)
		case syntax.InstFail:
		}
	}

	f.states[pc], f.done[pc] = states, true

	return states, true
}

// instRuneRanges returns the runes that inst accepts, as sorted pairs
// of the first and the last rune of each range. The inst must consume
// a rune.
func instRuneRanges(inst *syntax.Inst) []rune {
	// A rune instruction holds one rune for a literal and range pairs
	// for a class. Only a literal can match without regard to case.
	if len(inst.Rune) != 1 {
		return inst.Rune
	}

	r0 := inst.Rune[0]
	runes := []rune{r0}

	if inst.Arg&uint32(syntax.FoldCase) != 0 {
		for r := unicode.SimpleFold(r0); r != r0; r = unicode.SimpleFold(r) {
			runes = append(runes, r)
		}
	}

	slices.Sort(runes)

	ranges := make([]rune, 0, 2*len(runes))
	for _, r := range runes {
		ranges = append(ranges, r, r)
	}

	return ranges
}

// runeRangesIntersect reports whether one rune lies in a range of a
// and in a range of b. Each argument holds sorted pairs of the first
// and the last rune of each range.
func runeRangesIntersect(a, b []rune) bool {
	i, j := 0, 0

	for i+1 < len(a) && j+1 < len(b) {
		switch {
		case a[i+1] < b[j]:
			i += 2
		case b[j+1] < a[i]:
			j += 2
		default:
			return true
		}
	}

	return false
}

// headerConflict returns the first HeaderMatches entry of a that
// changes a header that b reads, see [changesHeader]. The result is
// false when a has no such entry.
//
// The rule b reads each header that it requires. It also reads each
// header that one of its HeaderMatches entries compares to deny, log,
// or change the request. A [MismatchDELETE] entry without a value does
// none of the three. Header names do not depend on case.
//
// Two [MismatchREPLACE] entries with one name and one value do not
// conflict. The header holds that value after the first of the two
// rules, whichever rule runs first, so the second rule changes nothing.
func headerConflict(a, b ResolvedHTTPRule) (HeaderMatch, bool) {
	for _, hm := range a.HeaderMatches {
		if !changesHeader(hm) {
			continue
		}

		required := slices.ContainsFunc(b.Headers, func(h string) bool {
			return strings.EqualFold(h, hm.Name)
		})

		compared := slices.ContainsFunc(b.HeaderMatches, func(other HeaderMatch) bool {
			if !strings.EqualFold(other.Name, hm.Name) {
				return false
			}

			if hm.Mismatch == MismatchREPLACE && other.Mismatch == MismatchREPLACE && other.Value == hm.Value {
				return false
			}

			return other.Mismatch == "" || other.Mismatch == MismatchLOG || changesHeader(other)
		})

		if required || compared {
			return hm, true
		}
	}

	return HeaderMatch{}, false
}

// describeHTTPRule returns the Path, the Method, and the Host of r for
// an error message.
func describeHTTPRule(r ResolvedHTTPRule) string {
	var parts []string

	if r.Path != "" {
		parts = append(parts, fmt.Sprintf("path %q", r.Path))
	}

	if r.Method != "" {
		parts = append(parts, fmt.Sprintf("method %q", r.Method))
	}

	if r.Host != "" {
		parts = append(parts, fmt.Sprintf("host %q", r.Host))
	}

	if len(parts) == 0 {
		return "{}"
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

// validateMismatchRules checks the mismatch actions of the HTTP rules
// that reach one Envoy virtual host. The domain and the port name that
// virtual host in each error.
//
// Cilium runs every HTTP rule that a request matches, in an order of
// its own. Each rule sees the header changes of the rules before it.
// Envoy routes a request with one route, and that route compares the
// request that the client sent. The routes can therefore give the
// result of Cilium only when the following conditions hold for each two
// rules that have a mismatch action and can match one request, see
// [MismatchRuleSets].
//
//   - The two rules have one Path, or one of them has no Path, so that
//     one route can match both.
//   - No rule changes a header that the other rule reads, so that the
//     order of the two rules changes no result, see [headerConflict].
//
// The check also limits the rules of one set, and the HeaderMatches
// entries of one set that [combinesMismatchRoutes] reports. The number
// of Envoy routes doubles with each of them. The number of sets grows
// with the product of the rule counts, so the check also limits the
// route combinations of all sets of two or more rules, see
// [maxMismatchSharedRoutes]. A set of one rule holds the routes that
// the rule gets without the other rules, so it does not count.
func validateMismatchRules(rules []ResolvedHTTPRule, domain string, port int) error {
	overlaps := ruleSetCache.entry(rules).overlapsFor(rules)

	for n, i := range overlaps.candidates {
		for _, j := range overlaps.candidates[n+1:] {
			a, b := rules[i], rules[j]
			if overlaps.disjoint(i, j) {
				continue
			}

			if !pathsCombine(a, b) {
				return fmt.Errorf(
					"%w: port %d domain %q http rules %s and %s",
					ErrHTTPRuleMismatchPaths, port, domain, describeHTTPRule(a), describeHTTPRule(b),
				)
			}

			changer, reader := a, b

			hm, ok := headerConflict(changer, reader)
			if !ok {
				changer, reader = b, a
				hm, ok = headerConflict(changer, reader)
			}

			if ok {
				return fmt.Errorf(
					"%w: port %d domain %q http rule %s changes %q with mismatch %q, and http rule %s reads it",
					ErrHeaderMatchMismatchAcrossRules, port, domain,
					describeHTTPRule(changer), hm.Name, hm.Mismatch, describeHTTPRule(reader),
				)
			}
		}
	}

	var (
		err    error
		shared int
	)

	walkMismatchRuleSets(rules, overlaps, func(set []int) bool {
		if len(set) > maxMismatchRuleSet {
			err = fmt.Errorf(
				"%w: port %d domain %q has %d",
				ErrHTTPRuleMismatchTooMany, port, domain, len(set),
			)

			return false
		}

		combined := 0

		for _, i := range set {
			for _, hm := range rules[i].HeaderMatches {
				if combinesMismatchRoutes(hm) {
					combined++
				}
			}
		}

		if combined > maxMismatchCombinedHeaders {
			err = fmt.Errorf(
				"%w: port %d domain %q has %d in %d http rules",
				ErrHeaderMatchMismatchTooMany, port, domain, combined, len(set),
			)

			return false
		}

		if len(set) > 1 {
			shared += 1 << combined
		}

		if shared > maxMismatchSharedRoutes {
			err = fmt.Errorf(
				"%w: port %d domain %q has more than %d",
				ErrHTTPRuleMismatchRoutesTooMany, port, domain, maxMismatchSharedRoutes,
			)

			return false
		}

		return true
	})

	return err
}

// validateMismatchRuleSets runs [validateMismatchRules] on the HTTP
// rules of each Envoy virtual host. Terrarium builds the virtual hosts
// from the result of [Config.ResolveRulesForPort] for port 80, for
// port 443, and for each port of ports.
//
// The result of [validateMismatchRules] depends only on the HTTP rules
// and their order. It checks each rule list once, so the ports of a
// range with the same rules do not repeat the work. An error names the
// first domain and port that hold the rule list.
func (c *Config) validateMismatchRuleSets(ctx context.Context, ports []int) error {
	checked := make(map[string]bool)

	for _, port := range slices.Compact(slices.Sorted(slices.Values(append([]int{80, 443}, ports...)))) {
		for _, r := range c.ResolveRulesForPort(ctx, port) {
			key := httpRulesKey(r.HTTPRules)
			if checked[key] {
				continue
			}

			checked[key] = true

			err := validateMismatchRules(r.HTTPRules, r.Domain, port)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
