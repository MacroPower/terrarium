package firewall_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall"
)

var (
	testUIDs   = firewall.UIDs{Terrarium: 1000, Envoy: 999, Root: 0}
	testVMUIDs = firewall.UIDs{Envoy: 999, Root: 0, VMMode: true}
)

func egressRules(rules ...config.EgressRule) *[]config.EgressRule {
	return &rules
}

// ruleVerdict returns the VerdictKind for the terminal verdict in a rule.
func ruleVerdict(r *nftables.Rule) (expr.VerdictKind, string) {
	for _, e := range r.Exprs {
		if v, ok := e.(*expr.Verdict); ok {
			return v.Kind, v.Chain
		}
	}

	return -99, ""
}

// ruleHasMetaKey reports whether a rule contains a Meta expression
// with the given key.
func ruleHasMetaKey(r *nftables.Rule, key expr.MetaKey) bool {
	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == key {
			return true
		}
	}

	return false
}

// ruleHasRedir reports whether a rule contains a Redir expression.
func ruleHasRedir(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.Redir); ok {
			return true
		}
	}

	return false
}

// ruleHasLookup reports whether a rule contains a Lookup expression.
func ruleHasLookup(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.Lookup); ok {
			return true
		}
	}

	return false
}

// ruleHasCtState reports whether a rule loads conntrack state.
func ruleHasCtState(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if ct, ok := e.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
			return true
		}
	}

	return false
}

// ruleHasLog reports whether a rule contains a Log expression.
func ruleHasLog(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.Log); ok {
			return true
		}
	}

	return false
}

func TestApplyRules_Unrestricted(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{} // nil Egress = unrestricted

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Table created.
	require.Len(t, rec.tables, 1)
	assert.Equal(t, "terrarium", rec.tables[0].Name)
	assert.Equal(t, nftables.TableFamilyINet, rec.tables[0].Family)

	// Chains: input, output, nat_output, mangle, postrouting_guard
	// (no terrarium_output).
	names := rec.chainNames()
	assert.Contains(t, names, "input")
	assert.Contains(t, names, "output")
	assert.Contains(t, names, "nat_output")
	assert.Contains(t, names, "postrouting_guard")
	assert.NotContains(t, names, "terrarium_output")

	// No FQDN sets.
	assert.Empty(t, rec.sets)

	// OUTPUT chain ends with ACCEPT.
	outputRules := rec.rulesForChain("output")
	require.NotEmpty(t, outputRules)

	lastVerdict, _ := ruleVerdict(outputRules[len(outputRules)-1])
	assert.Equal(t, expr.VerdictAccept, lastVerdict)

	// No DROP in output.
	for _, r := range outputRules {
		v, _ := ruleVerdict(r)
		assert.NotEqual(t, expr.VerdictDrop, v, "unrestricted mode should not DROP")
	}

	// NAT: port 80, port 443, catch-all TCP REDIRECTs.
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(t, 3, redirCount, "should have REDIRECTs for port 80, 443, and catch-all")
}

func TestApplyRules_UnrestrictedWithLogging(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{Logging: true}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	outputRules := rec.rulesForChain("output")
	// Second-to-last should be LOG, last should be ACCEPT.
	require.GreaterOrEqual(t, len(outputRules), 2)
	assert.True(t, ruleHasLog(outputRules[len(outputRules)-2]))

	v, _ := ruleVerdict(outputRules[len(outputRules)-1])
	assert.Equal(t, expr.VerdictAccept, v)
}

func TestApplyRules_UnrestrictedWithTCPForwards(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		TCPForwards: []config.TCPForward{{Host: "example.com", Port: 3000}},
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	assert.Contains(t, rec.chainNames(), "nat_output")

	natRules := rec.rulesForChain("nat_output")
	// port 80, port 443, TCPForward port 3000, catch-all TCP = 4 REDIRECTs.
	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(t, 4, redirCount, "should have REDIRECTs for port 80, 443, TCPForward, and catch-all")
}

func TestApplyRules_Blocked(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "input")
	assert.Contains(t, names, "output")
	assert.NotContains(t, names, "terrarium_output")
	assert.NotContains(t, names, "nat_output")

	// OUTPUT ends with DROP.
	outputRules := rec.rulesForChain("output")
	require.NotEmpty(t, outputRules)

	v, _ := ruleVerdict(outputRules[len(outputRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)
}

func TestApplyRules_BlockedWithLogging(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress:  egressRules(config.EgressRule{}),
		Logging: true,
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	outputRules := rec.rulesForChain("output")
	require.GreaterOrEqual(t, len(outputRules), 2)
	assert.True(t, ruleHasLog(outputRules[len(outputRules)-2]))

	v, _ := ruleVerdict(outputRules[len(outputRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)
}

func TestApplyRules_RulesMode(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDRSet: []config.CIDRRule{
				{CIDR: "0.0.0.0/0", Except: []string{
					"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
				}},
				{CIDR: "::/0", Except: []string{"fc00::/7", "fe80::/10"}},
			}},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "80"}, {Port: "443"}, {Port: "8080"},
				}}},
			},
		),
		Logging: true,
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "input")
	assert.Contains(t, names, "output")
	assert.Contains(t, names, "terrarium_output")
	assert.Contains(t, names, "cidr_0")
	assert.Contains(t, names, "nat_output")

	// OUTPUT chain: verify UID 1000 dispatch to terrarium_output
	// appears before ESTABLISHED.
	outputRules := rec.rulesForChain("output")

	var jumpIdx, estIdx int
	for i, r := range outputRules {
		v, chain := ruleVerdict(r)
		if v == expr.VerdictJump && chain == "terrarium_output" {
			jumpIdx = i
		}

		if ruleHasCtState(r) && v == expr.VerdictAccept && !ruleHasMetaKey(r, expr.MetaKeySKUID) {
			estIdx = i
			break // first ESTABLISHED accept
		}
	}

	assert.Greater(t, estIdx, jumpIdx,
		"UID 1000 dispatch must come before ESTABLISHED accept")

	// OUTPUT ends with DROP.
	v, _ := ruleVerdict(outputRules[len(outputRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)

	// terrarium_output ends with DROP.
	terrariumRules := rec.rulesForChain("terrarium_output")
	require.NotEmpty(t, terrariumRules)

	v, _ = ruleVerdict(terrariumRules[len(terrariumRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)

	// terrarium_output has jump to cidr_0.
	var hasCIDRJump bool
	for _, r := range terrariumRules {
		vk, chain := ruleVerdict(r)
		if vk == expr.VerdictJump && chain == "cidr_0" {
			hasCIDRJump = true
			break
		}
	}

	assert.True(t, hasCIDRJump, "terrarium_output must jump to cidr_0")

	// cidr_0 chain has RETURN for excepts and ACCEPT for CIDRs.
	cidrRules := rec.rulesForChain("cidr_0")
	require.NotEmpty(t, cidrRules)

	var hasReturn, hasAccept bool
	for _, r := range cidrRules {
		vk, _ := ruleVerdict(r)
		if vk == expr.VerdictReturn {
			hasReturn = true
		}

		if vk == expr.VerdictAccept {
			hasAccept = true
		}
	}

	assert.True(t, hasReturn, "cidr_0 should have RETURN for excepts")
	assert.True(t, hasAccept, "cidr_0 should have ACCEPT for CIDRs")

	// Verify RETURN appears before ACCEPT in cidr chain (except
	// before allow).
	firstReturn, firstAccept := -1, -1
	for i, r := range cidrRules {
		vk, _ := ruleVerdict(r)
		if vk == expr.VerdictReturn && firstReturn == -1 {
			firstReturn = i
		}

		if vk == expr.VerdictAccept && firstAccept == -1 {
			firstAccept = i
		}
	}

	assert.Less(t, firstReturn, firstAccept,
		"except RETURN must precede CIDR ACCEPT")

	// NAT: verify REDIRECT rules exist.
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(t, 4, redirCount, "should have REDIRECTs for ports 80, 443, 8080, and catch-all")

	// NAT: verify RETURN for CIDRs appears before REDIRECT.
	firstNATReturn, firstNATRedir := -1, -1
	for i, r := range natRules {
		vk, _ := ruleVerdict(r)
		if vk == expr.VerdictReturn && firstNATReturn == -1 {
			firstNATReturn = i
		}

		if ruleHasRedir(r) && firstNATRedir == -1 {
			firstNATRedir = i
		}
	}

	if firstNATReturn >= 0 {
		assert.Less(t, firstNATReturn, firstNATRedir,
			"NAT RETURN must precede REDIRECT")
	}

	// Logging: terrarium_output has LOG before DROP.
	assert.True(t, ruleHasLog(terrariumRules[len(terrariumRules)-2]))
}

func TestApplyRules_RulesMode_EnvoyAcceptPlacement(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	outputRules := rec.rulesForChain("output")

	// Envoy ACCEPT (UID 999) must be in the output chain, placed
	// before the UID 1000 dispatch and before ESTABLISHED. Envoy
	// is excluded first so its traffic never enters policy
	// evaluation. Only UID 1000 enters terrarium_output.
	envoyIdx, terrariumJumpIdx, estIdx := -1, -1, -1
	for i, r := range outputRules {
		vk, chain := ruleVerdict(r)
		if vk == expr.VerdictJump && chain == "terrarium_output" {
			terrariumJumpIdx = i
		}

		if envoyIdx == -1 && vk == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			envoyIdx = i
		}

		if ruleHasCtState(r) && vk == expr.VerdictAccept && !ruleHasMetaKey(r, expr.MetaKeySKUID) {
			estIdx = i
			break
		}
	}

	require.NotEqual(t, -1, envoyIdx, "Envoy ACCEPT must exist in output chain")
	require.NotEqual(t, -1, terrariumJumpIdx, "terrarium_output jump must exist")
	require.NotEqual(t, -1, estIdx, "ESTABLISHED ACCEPT must exist")

	assert.Less(t, envoyIdx, terrariumJumpIdx,
		"Envoy ACCEPT must come before UID 1000 dispatch")
	assert.Less(t, envoyIdx, estIdx,
		"Envoy ACCEPT must come before ESTABLISHED")
}

func TestApplyRules_FQDNSets(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "UDP"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// FQDN sets created (v4 + v6).
	setNames := rec.setNames()
	assert.Contains(t, setNames, "terrarium_fqdn4_0")
	assert.Contains(t, setNames, "terrarium_fqdn6_0")

	// Sets have correct key types.
	for _, s := range rec.sets {
		if s.Name == "terrarium_fqdn4_0" {
			assert.Equal(t, nftables.TypeIPAddr, s.KeyType)
			assert.True(t, s.HasTimeout)
		}

		if s.Name == "terrarium_fqdn6_0" {
			assert.Equal(t, nftables.TypeIP6Addr, s.KeyType)
			assert.True(t, s.HasTimeout)
		}
	}

	// terrarium_output has FQDN set lookup rules.
	terrariumRules := rec.rulesForChain("terrarium_output")

	var lookupCount int
	for _, r := range terrariumRules {
		if ruleHasLookup(r) {
			lookupCount++
		}
	}

	assert.Equal(t, 2, lookupCount, "should have v4 and v6 set lookup rules")
}

func TestApplyRules_FQDNZombieCTOrdering(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "UDP"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	terrariumRules := rec.rulesForChain("terrarium_output")

	// Find ESTABLISHED and Lookup rule positions for FQDN port.
	estIdx, lookupIdx := -1, -1
	for i, r := range terrariumRules {
		if ruleHasCtState(r) && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			if estIdx == -1 {
				estIdx = i
			}
		}

		if ruleHasLookup(r) && lookupIdx == -1 {
			lookupIdx = i
		}
	}

	require.NotEqual(t, -1, estIdx, "should have ESTABLISHED rule for FQDN port")
	require.NotEqual(t, -1, lookupIdx, "should have Lookup rule for FQDN port")
	assert.Less(t, estIdx, lookupIdx,
		"ESTABLISHED must come before Lookup (zombie/CT semantics)")
}

func TestApplyRules_UnrestrictedOpenPorts(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			// Port-only rule (no L3 selector) = unrestricted open port.
			config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443"},
				}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// When HasUnrestrictedOpenPorts(), CIDR chains are skipped.
	names := rec.chainNames()
	assert.NotContains(t, names, "cidr_0")

	// terrarium_output has blanket UID 1000 ACCEPT.
	terrariumRules := rec.rulesForChain("terrarium_output")

	var hasBlanketAccept bool
	for _, r := range terrariumRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			hasBlanketAccept = true
		}
	}

	assert.True(t, hasBlanketAccept,
		"unrestricted open ports should have blanket UID 1000 ACCEPT")
}

func TestApplyRules_OpenTCPSinglePortGoThroughEnvoy(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			// Open TCP port (no L3 selector).
			config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "TCP"},
				}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// NAT should have CIDR RETURN (for security), per-port REDIRECT,
	// and catch-all REDIRECT. No open-port-specific RETURN rules.
	natRules := rec.rulesForChain("nat_output")

	// Count port-specific RETURN vs CIDR RETURN. Port-specific
	// RETURN rules match a destination port; CIDR RETURN rules
	// match a destination CIDR. With the new behavior, only CIDR
	// RETURNs should exist.
	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	// Per-port REDIRECT (443) + catch-all REDIRECT = 2.
	assert.Equal(t, 2, redirCount,
		"should have per-port REDIRECT and catch-all REDIRECT")
}

func TestApplyRules_TCPForwards(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
		TCPForwards: []config.TCPForward{
			{Host: "db.example.com", Port: 5432},
		},
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	natRules := rec.rulesForChain("nat_output")

	// TCPForward REDIRECT should appear after Envoy REDIRECT.
	envoyRedirIdx, fwdRedirIdx := -1, -1
	for i, r := range natRules {
		if !ruleHasRedir(r) {
			continue
		}

		if envoyRedirIdx == -1 {
			envoyRedirIdx = i
		}

		fwdRedirIdx = i // last redirect is the TCPForward
	}

	require.NotEqual(t, -1, envoyRedirIdx)
	require.NotEqual(t, -1, fwdRedirIdx)
	assert.Greater(t, fwdRedirIdx, envoyRedirIdx,
		"TCPForward REDIRECT should appear after Envoy REDIRECT")
}

func TestApplyRules_InputChain(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	inputRules := rec.rulesForChain("input")
	require.Len(t, inputRules, 2)

	// First rule: match iifname -> ACCEPT.
	v, _ := ruleVerdict(inputRules[0])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleHasMetaKey(inputRules[0], expr.MetaKeyIIFNAME))

	// Second rule: ct state established,related -> ACCEPT.
	v, _ = ruleVerdict(inputRules[1])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleHasCtState(inputRules[1]))
}

func TestApplyRules_PerRuleFQDNSetIsolation(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "a.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "5000", Protocol: "UDP"},
				}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "b.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "6000", Protocol: "UDP"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Each FQDN rule should get its own pair of sets.
	setNames := rec.setNames()
	assert.Contains(t, setNames, "terrarium_fqdn4_0")
	assert.Contains(t, setNames, "terrarium_fqdn6_0")
	assert.Contains(t, setNames, "terrarium_fqdn4_1")
	assert.Contains(t, setNames, "terrarium_fqdn6_1")
}

func TestApplyRules_OpenPortFilterRules(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			// UDP open port.
			config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "5000", Protocol: "UDP"},
				}}},
			},
			// TCP port range.
			config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "8000", EndPort: 9000, Protocol: "TCP"},
				}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "TCP"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	terrariumRules := rec.rulesForChain("terrarium_output")

	// Count ACCEPT rules that have UID matching (open port rules).
	var acceptCount int
	for _, r := range terrariumRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			acceptCount++
		}
	}

	// Should have: UDP open port ACCEPT + TCP range ACCEPT = 2.
	// Envoy ACCEPT is in the output chain, not terrarium_output.
	// The FQDN rule is TCP-only so no set lookup rules are generated.
	assert.Equal(t, 2, acceptCount)
}

func TestApplyRules_MultipleRuleCIDRChains(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			config.EgressRule{ToCIDRSet: []config.CIDRRule{
				{CIDR: "172.16.0.0/12", Except: []string{"172.16.1.0/24"}},
			}},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Two separate CIDR chains for two CIDR rules.
	names := rec.chainNames()
	assert.Contains(t, names, "cidr_0")
	assert.Contains(t, names, "cidr_1")

	// Both get jumped from terrarium_output.
	terrariumRules := rec.rulesForChain("terrarium_output")

	var jumpChains []string
	for _, r := range terrariumRules {
		v, chain := ruleVerdict(r)
		if v == expr.VerdictJump {
			jumpChains = append(jumpChains, chain)
		}
	}

	assert.Contains(t, jumpChains, "cidr_0")
	assert.Contains(t, jumpChains, "cidr_1")
}

func TestApplyRules_CIDROnlyFilteredMode(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			config.EgressRule{ToCIDRSet: []config.CIDRRule{
				{CIDR: "172.16.0.0/12", Except: []string{"172.16.1.0/24"}},
			}},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// NAT chain exists even with zero resolved ports.
	assert.Contains(t, rec.chainNames(), "nat_output")

	// CIDR NAT redirect chains exist (one per rule group).
	assert.Contains(t, rec.chainNames(), "cidr_nat_0")
	assert.Contains(t, rec.chainNames(), "cidr_nat_1")

	// CIDR NAT chains have TCP REDIRECT rules to CIDR catch-all.
	for _, chainName := range []string{"cidr_nat_0", "cidr_nat_1"} {
		cidrNATRules := rec.rulesForChain(chainName)
		require.NotEmpty(t, cidrNATRules, "chain %s should have rules", chainName)

		var hasRedir bool
		for _, r := range cidrNATRules {
			if ruleHasRedir(r) {
				hasRedir = true
			}
		}

		assert.True(t, hasRedir, "chain %s should have REDIRECT rules", chainName)
	}

	// nat_output should have jumps to CIDR NAT chains and catch-all REDIRECT.
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	var hasJump, hasRedir bool
	for _, r := range natRules {
		v, chain := ruleVerdict(r)
		if v == expr.VerdictJump && (chain == "cidr_nat_0" || chain == "cidr_nat_1") {
			hasJump = true
		}

		if ruleHasRedir(r) {
			hasRedir = true
		}
	}

	assert.True(t, hasJump, "should have jumps to CIDR NAT chains")
	assert.True(t, hasRedir, "should have catch-all REDIRECT")
}

// ruleHasTProxy reports whether a rule contains a TProxy expression.
func ruleHasTProxy(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.TProxy); ok {
			return true
		}
	}

	return false
}

// ruleHasMark reports whether a rule contains a Meta expression that
// sets or reads the fwmark.
func ruleHasMark(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyMARK {
			return true
		}
	}

	return false
}

func TestApplyRules_MangleChains_Unrestricted(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "mangle_output")
	assert.Contains(t, names, "mangle_prerouting")

	// mangle_output should mark UDP packets.
	mangleRules := rec.rulesForChain("mangle_output")
	require.NotEmpty(t, mangleRules)

	var hasMarkSet bool
	for _, r := range mangleRules {
		if ruleHasMark(r) {
			hasMarkSet = true
		}
	}

	assert.True(t, hasMarkSet, "mangle_output should set fwmark")

	// mangle_prerouting should have TPROXY rules.
	preRules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, preRules)

	var tproxyCount int
	for _, r := range preRules {
		if ruleHasTProxy(r) {
			tproxyCount++
		}
	}

	assert.Equal(t, 2, tproxyCount, "should have IPv4 and IPv6 TPROXY rules")
}

func TestApplyRules_MangleChains_Filtered(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "mangle_output")
	assert.Contains(t, names, "mangle_prerouting")
	assert.Contains(t, names, "postrouting_guard")

	// Filtered mode: loopback accept in output should exclude
	// TPROXY-marked packets (fwmark != 0x1).
	outputRules := rec.rulesForChain("output")
	require.NotEmpty(t, outputRules)

	// First rule should be the loopback accept with mark exclusion.
	firstRule := outputRules[0]
	assert.True(t, ruleHasMetaKey(firstRule, expr.MetaKeyOIFNAME),
		"first output rule should match oifname")
	assert.True(t, ruleHasMark(firstRule),
		"first output rule should check fwmark (mark exclusion)")

	// Verify the mark comparison is CmpOpNeq with value 0x1.
	var foundMarkNeq bool

	for _, e := range firstRule.Exprs {
		c, ok := e.(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpNeq {
			continue
		}

		// The mark value 0x1 in native endian (4 bytes).
		markVal := binaryutil.NativeEndian.PutUint32(0x1)
		if assert.ObjectsAreEqual(markVal, c.Data) {
			foundMarkNeq = true
		}
	}

	assert.True(t, foundMarkNeq,
		"loopback accept must exclude fwmark 0x1 via CmpOpNeq")
}

func TestApplyRules_MangleChains_Blocked(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.NotContains(t, names, "mangle_output",
		"blocked mode should not have mangle chains")
	assert.NotContains(t, names, "mangle_prerouting",
		"blocked mode should not have mangle chains")
}

func TestApplyRules_MangleChains_DNSExclusion(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// mangle_output should have a port 53 exclusion (CmpOpNeq on
	// dst port).
	mangleRules := rec.rulesForChain("mangle_output")
	require.NotEmpty(t, mangleRules)

	var hasDstPortNeq bool
	for _, r := range mangleRules {
		for _, e := range r.Exprs {
			if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpNeq {
				hasDstPortNeq = true
			}
		}
	}

	assert.True(t, hasDstPortNeq, "mangle_output should exclude port 53 via CmpOpNeq")
}

func TestApplyRules_CIDRWithPorts(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToCIDR: []string{"10.0.0.0/8"},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "TCP"},
					{Port: "80", Protocol: "TCP"},
				}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	cidrRules := rec.rulesForChain("cidr_0")
	// With 2 ports on one CIDR, we get 2 ACCEPT rules (one per port).
	var acceptCount int
	for _, r := range cidrRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept {
			acceptCount++
		}
	}

	assert.Equal(t, 2, acceptCount)
}

func TestApplyRules_ICMPOnly(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ICMPs: []config.ICMPRule{{
				Fields: []config.ICMPField{
					{Family: "IPv4", Type: "8"},
					{Family: "IPv6", Type: "128"},
				},
			}},
		}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// ICMP rules should appear in terrarium_output chain.
	outputRules := rec.rulesForChain("terrarium_output")

	var icmpAccepts int
	for _, r := range outputRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasPayload(r) {
			icmpAccepts++
		}
	}

	// Two ICMP ACCEPTs: one IPv4 type 8, one IPv6 type 128.
	assert.Equal(t, 2, icmpAccepts)
}

func TestApplyRules_DenyICMP(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	denyRules := []config.EgressDenyRule{{
		ICMPs: []config.ICMPRule{{
			Fields: []config.ICMPField{
				{Family: "IPv4", Type: "8"},
			},
		}},
	}}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToCIDR: []string{"10.0.0.0/8"},
		}),
		EgressDeny: &denyRules,
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Deny ICMP rules appear in terrarium_output chain as DROPs.
	outputRules := rec.rulesForChain("terrarium_output")

	var icmpDrops int
	for _, r := range outputRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictDrop && ruleHasPayload(r) {
			icmpDrops++
		}
	}

	assert.Equal(t, 1, icmpDrops)
}

func TestApplyRules_ICMPWithCIDR(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToCIDR: []string{"10.0.0.0/8"},
				ICMPs: []config.ICMPRule{{
					Fields: []config.ICMPField{
						{Family: "IPv4", Type: "8"},
					},
				}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// CIDR chain created for the CIDR part.
	cidrRules := rec.rulesForChain("cidr_0")
	assert.NotEmpty(t, cidrRules, "CIDR chain should be created")

	// ICMP with CIDRs uses a per-rule chain instead of flat rules
	// on the output chain.
	icmpChainRules := rec.rulesForChain("icmp_0")
	assert.NotEmpty(t, icmpChainRules, "ICMP chain should be created for CIDR-scoped rule")

	// The ICMP chain should have a CIDR-scoped ACCEPT with payload.
	var icmpAccepts int
	for _, r := range icmpChainRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasPayload(r) {
			icmpAccepts++
		}
	}

	assert.Equal(t, 1, icmpAccepts)
}

func TestApplyRules_ICMPWithoutCIDR(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ICMPs: []config.ICMPRule{{
					Fields: []config.ICMPField{
						{Family: "IPv4", Type: "8"},
					},
				}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Standalone ICMP (no CIDRs) should be flat on the output chain.
	outputRules := rec.rulesForChain("terrarium_output")

	var icmpAccepts int
	for _, r := range outputRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasPayload(r) {
			icmpAccepts++
		}
	}

	assert.Equal(t, 1, icmpAccepts)
}

// ruleMatchesUID reports whether a rule matches a specific UID value
// by checking for a Meta SKUID load followed by a Cmp with the UID
// value in native endian.
func ruleMatchesUID(r *nftables.Rule, uid uint32) bool {
	hasMetaSKUID := false

	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeySKUID {
			hasMetaSKUID = true
		}

		if hasMetaSKUID {
			if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq {
				expected := binaryutil.NativeEndian.PutUint32(uid)
				if assert.ObjectsAreEqual(expected, c.Data) {
					return true
				}
			}
		}
	}

	return false
}

// ruleHasPayload reports whether a rule contains a Payload expression
// (used by ICMP type matching).
func ruleHasPayload(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.Payload); ok {
			return true
		}
	}

	return false
}

func TestApplyRules_ICMPWithFQDN(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
			ICMPs: []config.ICMPRule{{
				Fields: []config.ICMPField{
					{Family: "IPv4", Type: "8"},
					{Family: "IPv6", Type: "128"},
				},
			}},
		}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// ICMP FQDN sets should be created.
	setNames := rec.setNames()
	assert.Contains(t, setNames, "terrarium_fqdnicmp4_0")
	assert.Contains(t, setNames, "terrarium_fqdnicmp6_0")

	// terrarium_output should have ICMP ESTABLISHED and set lookup
	// rules. The rule also qualifies as catch-all FQDN, so both
	// ICMP FQDN and catch-all sets are created.
	assert.Contains(t, setNames, "terrarium_fqdnca4_0")
	assert.Contains(t, setNames, "terrarium_fqdnca6_0")

	outputRules := rec.rulesForChain("terrarium_output")

	// Count lookup rules that include ICMP type matching (Payload
	// at ICMP offset). ICMP FQDN lookups have matchICMPType +
	// setLookupDst, producing two Payload expressions per rule.
	var icmpLookups int
	for _, r := range outputRules {
		payloadCount := 0
		hasLookup := false

		for _, e := range r.Exprs {
			if _, ok := e.(*expr.Payload); ok {
				payloadCount++
			}

			if _, ok := e.(*expr.Lookup); ok {
				hasLookup = true
			}
		}

		// ICMP FQDN lookup rules have 2 Payload expressions:
		// one for ICMP type matching, one for dst IP set lookup.
		if hasLookup && payloadCount >= 2 {
			icmpLookups++
		}
	}

	// One v4 lookup (IPv4 type 8) and one v6 lookup (IPv6 type 128).
	assert.Equal(t, 2, icmpLookups, "should have ICMP FQDN set lookup rules")
}

func TestApplyRules_PostroutingGuard(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg       *config.Config
		wantChain bool
		wantLog   bool
	}{
		"unrestricted": {
			cfg:       &config.Config{},
			wantChain: true,
		},
		"unrestricted with logging": {
			cfg:       &config.Config{Logging: true},
			wantChain: true,
			wantLog:   true,
		},
		"filtered": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			wantChain: true,
		},
		"filtered with logging": {
			cfg: &config.Config{
				Logging: true,
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			wantChain: true,
			wantLog:   true,
		},
		"blocked": {
			cfg:       &config.Config{Egress: egressRules(config.EgressRule{})},
			wantChain: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tt.cfg, testUIDs)
			require.NoError(t, err)

			// Find the postrouting_guard chain.
			var guardChain *nftables.Chain
			for _, c := range rec.chains {
				if c.Name == "postrouting_guard" {
					guardChain = c
					break
				}
			}

			if !tt.wantChain {
				assert.Nil(t, guardChain, "blocked mode should not have postrouting_guard")
				return
			}

			require.NotNil(t, guardChain, "postrouting_guard chain should exist")
			assert.Equal(t, nftables.ChainHookPostrouting, guardChain.Hooknum)
			assert.Equal(t, nftables.ChainPolicyAccept, *guardChain.Policy)

			rules := rec.rulesForChain("postrouting_guard")
			require.NotEmpty(t, rules)

			// Last rule should be DROP with oifname != "lo" and UID match.
			lastRule := rules[len(rules)-1]
			v, _ := ruleVerdict(lastRule)
			assert.Equal(t, expr.VerdictDrop, v)
			assert.True(t, ruleHasMetaKey(lastRule, expr.MetaKeyOIFNAME),
				"DROP rule should match oifname")
			assert.True(t, ruleHasMetaKey(lastRule, expr.MetaKeySKUID),
				"DROP rule should match UID")

			// Verify oifname comparison is CmpOpNeq (not equal to "lo").
			var foundOIFNeq bool
			for _, e := range lastRule.Exprs {
				c, ok := e.(*expr.Cmp)
				if !ok || c.Op != expr.CmpOpNeq {
					continue
				}

				// "lo" padded to IFNAMSIZ (16 bytes).
				if len(c.Data) == 16 && c.Data[0] == 'l' && c.Data[1] == 'o' && c.Data[2] == 0 {
					foundOIFNeq = true
				}
			}

			assert.True(t, foundOIFNeq, "DROP rule must use CmpOpNeq for oifname != lo")

			// LOG rule presence.
			var hasLog bool
			for _, r := range rules {
				if ruleHasLog(r) {
					hasLog = true
				}
			}

			assert.Equal(t, tt.wantLog, hasLog,
				"LOG rule presence should match logging config")
		})
	}
}

func TestApplyRules_VMMode_Filtered(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "terrarium_output")
	assert.Contains(t, names, "nat_output")

	outputRules := rec.rulesForChain("output")

	// Envoy ACCEPT must appear before the jump to terrarium_output.
	envoyIdx, jumpIdx := -1, -1
	for i, r := range outputRules {
		v, chain := ruleVerdict(r)
		if envoyIdx == -1 && v == expr.VerdictAccept && ruleMatchesUID(r, testVMUIDs.Envoy) {
			envoyIdx = i
		}

		if v == expr.VerdictJump && chain == "terrarium_output" {
			jumpIdx = i
		}
	}

	require.NotEqual(t, -1, envoyIdx, "Envoy ACCEPT must exist")
	require.NotEqual(t, -1, jumpIdx, "terrarium_output jump must exist")
	assert.Less(t, envoyIdx, jumpIdx,
		"Envoy ACCEPT must come before terrarium_output jump")

	// Root DNS accept and CT established must appear before the
	// unconditional jump to terrarium_output, otherwise the jump
	// intercepts root DNS queries and established connections.
	rootDNSIdx, ctEstabIdx := -1, -1
	for i, r := range outputRules {
		if rootDNSIdx == -1 && ruleMatchesUID(r, testVMUIDs.Root) {
			v, _ := ruleVerdict(r)
			if v == expr.VerdictAccept {
				rootDNSIdx = i
			}
		}

		if ctEstabIdx == -1 && ruleHasCtState(r) {
			v, _ := ruleVerdict(r)
			if v == expr.VerdictAccept {
				ctEstabIdx = i
			}
		}
	}

	require.NotEqual(t, -1, rootDNSIdx, "root DNS ACCEPT must exist")
	require.NotEqual(t, -1, ctEstabIdx, "CT established ACCEPT must exist")
	assert.Less(t, rootDNSIdx, jumpIdx,
		"root DNS ACCEPT must come before terrarium_output jump")
	assert.Less(t, ctEstabIdx, jumpIdx,
		"CT established ACCEPT must come before terrarium_output jump")

	// The jump to terrarium_output must NOT have a UID match
	// (all non-Envoy traffic enters the policy chain in VM mode).
	jumpRule := outputRules[jumpIdx]
	assert.False(t, ruleHasMetaKey(jumpRule, expr.MetaKeySKUID),
		"VM mode jump to terrarium_output should not match UID")

	// terrarium_output ends with DROP.
	terrariumRules := rec.rulesForChain("terrarium_output")
	require.NotEmpty(t, terrariumRules)

	v, _ := ruleVerdict(terrariumRules[len(terrariumRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)

	// Rules inside terrarium_output should NOT have UID matching
	// (matchFilteredTraffic returns nil in VM mode).
	for _, r := range terrariumRules {
		assert.False(t, ruleHasMetaKey(r, expr.MetaKeySKUID),
			"VM mode terrarium_output rules should not match UID")
	}
}

func TestApplyRules_VMMode_NATExclusions(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	// First two rules should be Envoy and root UID ACCEPTs.
	require.GreaterOrEqual(t, len(natRules), 2)

	v0, _ := ruleVerdict(natRules[0])
	assert.Equal(t, expr.VerdictAccept, v0)
	assert.True(t, ruleMatchesUID(natRules[0], testVMUIDs.Envoy),
		"first NAT rule should accept Envoy UID")

	v1, _ := ruleVerdict(natRules[1])
	assert.Equal(t, expr.VerdictAccept, v1)
	assert.True(t, ruleMatchesUID(natRules[1], testVMUIDs.Root),
		"second NAT rule should accept root UID")

	// REDIRECT rules should NOT have UID matching.
	for _, r := range natRules[2:] {
		if ruleHasRedir(r) {
			assert.False(t, ruleHasMetaKey(r, expr.MetaKeySKUID),
				"VM mode NAT REDIRECT rules should not match UID")
		}
	}
}

func TestApplyRules_VMMode_MangleExclusions(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	mangleRules := rec.rulesForChain("mangle_output")
	require.NotEmpty(t, mangleRules)

	// First two rules should ACCEPT Envoy and root UIDs.
	require.GreaterOrEqual(t, len(mangleRules), 3)

	v0, _ := ruleVerdict(mangleRules[0])
	assert.Equal(t, expr.VerdictAccept, v0)
	assert.True(t, ruleMatchesUID(mangleRules[0], testVMUIDs.Envoy),
		"first mangle rule should accept Envoy UID")

	v1, _ := ruleVerdict(mangleRules[1])
	assert.Equal(t, expr.VerdictAccept, v1)
	assert.True(t, ruleMatchesUID(mangleRules[1], testVMUIDs.Root),
		"second mangle rule should accept root UID")

	// The mark rule should NOT have UID matching.
	markRule := mangleRules[2]
	assert.True(t, ruleHasMark(markRule), "third mangle rule should set mark")
	assert.False(t, ruleHasMetaKey(markRule, expr.MetaKeySKUID),
		"VM mode mark rule should not match UID")
}

func TestApplyRules_VMMode_PostroutingGuard(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	rules := rec.rulesForChain("postrouting_guard")
	require.NotEmpty(t, rules)

	// First two rules should ACCEPT Envoy and root UIDs.
	require.GreaterOrEqual(t, len(rules), 3)

	v0, _ := ruleVerdict(rules[0])
	assert.Equal(t, expr.VerdictAccept, v0)
	assert.True(t, ruleMatchesUID(rules[0], testVMUIDs.Envoy),
		"first postrouting rule should accept Envoy UID")

	v1, _ := ruleVerdict(rules[1])
	assert.Equal(t, expr.VerdictAccept, v1)
	assert.True(t, ruleMatchesUID(rules[1], testVMUIDs.Root),
		"second postrouting rule should accept root UID")

	// Last rule should be DROP without UID matching (all remaining
	// traffic on non-loopback).
	lastRule := rules[len(rules)-1]
	v, _ := ruleVerdict(lastRule)
	assert.Equal(t, expr.VerdictDrop, v)
	assert.False(t, ruleHasMetaKey(lastRule, expr.MetaKeySKUID),
		"VM mode postrouting DROP should not match specific UID")
}

func TestApplyRules_VMMode_Unrestricted(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	// NAT chain should have Envoy and root exclusions.
	natRules := rec.rulesForChain("nat_output")
	require.GreaterOrEqual(t, len(natRules), 2)
	assert.True(t, ruleMatchesUID(natRules[0], testVMUIDs.Envoy))
	assert.True(t, ruleMatchesUID(natRules[1], testVMUIDs.Root))

	// REDIRECT rules should not have UID matching.
	for _, r := range natRules[2:] {
		if ruleHasRedir(r) {
			assert.False(t, ruleHasMetaKey(r, expr.MetaKeySKUID),
				"VM mode NAT REDIRECT should not match UID")
		}
	}
}

func TestApplyRules_VMMode_Blocked(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	outputRules := rec.rulesForChain("output")
	require.NotEmpty(t, outputRules)

	// Should have Envoy ACCEPT before terminal DROP.
	var envoyAcceptIdx, dropIdx int

	for i, r := range outputRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleMatchesUID(r, testVMUIDs.Envoy) {
			envoyAcceptIdx = i
		}

		if v == expr.VerdictDrop {
			dropIdx = i
		}
	}

	assert.Less(t, envoyAcceptIdx, dropIdx,
		"Envoy ACCEPT must come before terminal DROP in VM blocked mode")
}
