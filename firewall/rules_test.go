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

	// Chains: output, nat_output, mangle, postrouting_guard
	// (no terrarium_output).
	names := rec.chainNames()
	assert.NotContains(t, names, "input")
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

	// NAT: DNS UDP, DNS TCP, port 80, port 443, catch-all TCP REDIRECTs.
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(t, 5, redirCount, "should have REDIRECTs for DNS UDP, DNS TCP, port 80, 443, and catch-all")
}

func TestApplyRules_UnrestrictedWithLogging(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{Logging: &config.LoggingConfig{Firewall: &config.FirewallLogging{Enabled: true}}}

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
	// DNS UDP, DNS TCP, port 80, port 443, TCPForward port 3000, catch-all TCP = 6 REDIRECTs.
	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(
		t, 6, redirCount,
		"should have REDIRECTs for DNS UDP, DNS TCP, port 80, 443, TCPForward, and catch-all",
	)
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
	assert.NotContains(t, names, "input")
	assert.Contains(t, names, "output")
	assert.NotContains(t, names, "terrarium_output")
	assert.Contains(t, names, "nat_output")

	// NAT: DNS REDIRECT (UDP + TCP).
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules)

	var redirCount int
	for _, r := range natRules {
		if ruleHasRedir(r) {
			redirCount++
		}
	}

	assert.Equal(t, 2, redirCount, "should have DNS UDP and DNS TCP REDIRECTs")

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
		Logging: &config.LoggingConfig{Firewall: &config.FirewallLogging{Enabled: true}},
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	// Blocked mode with logging should still have nat_output for DNS REDIRECT.
	names := rec.chainNames()
	assert.Contains(t, names, "nat_output")

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
		Logging: &config.LoggingConfig{Firewall: &config.FirewallLogging{Enabled: true}},
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.NotContains(t, names, "input")
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

	assert.Equal(t, 6, redirCount, "should have REDIRECTs for DNS UDP, DNS TCP, ports 80, 443, 8080, and catch-all")

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

	// DNS UDP, DNS TCP, per-port REDIRECT (443), catch-all REDIRECT = 4.
	assert.Equal(t, 4, redirCount,
		"should have DNS UDP, DNS TCP, per-port REDIRECT, and catch-all REDIRECT")
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

			v, _ := ruleVerdict(r)
			assert.Equal(t, expr.VerdictAccept, v,
				"TPROXY rule should accept to prevent catch-all override")
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

	// Filtered mode: no blanket oifname "lo" accept. Traffic to
	// non-loopback IPs on lo must reach policy evaluation so deny
	// rules can fire. Only 127.0.0.0/8 and ::1 are accepted.
	outputRules := rec.rulesForChain("output")
	require.NotEmpty(t, outputRules)

	// First rule is the guard mark (no oifname); filtered mode omits
	// the blanket oifname "lo" accept.
	firstRule := outputRules[0]
	assert.False(t, ruleHasMetaKey(firstRule, expr.MetaKeyOIFNAME),
		"filtered mode should not have oifname lo accept")
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
			cfg:       &config.Config{Logging: &config.LoggingConfig{Firewall: &config.FirewallLogging{Enabled: true}}},
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
				Logging: &config.LoggingConfig{Firewall: &config.FirewallLogging{Enabled: true}},
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

			// ICMP accept rules should exist before the log/drop rules.
			var icmpAccept, icmpv6Accept bool
			for _, r := range rules {
				rv, _ := ruleVerdict(r)
				if rv != expr.VerdictAccept {
					continue
				}

				if ruleMatchesL4Proto(r, 1) { // IPPROTO_ICMP
					icmpAccept = true
				}

				if ruleMatchesL4Proto(r, 58) { // IPPROTO_ICMPV6
					icmpv6Accept = true
				}
			}

			assert.True(t, icmpAccept, "postrouting_guard should accept ICMP")
			assert.True(t, icmpv6Accept, "postrouting_guard should accept ICMPv6")
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

	// First two rules should ACCEPT Envoy and root UIDs, plus ICMP/ICMPv6 accepts and drop.
	require.GreaterOrEqual(t, len(rules), 5)

	v0, _ := ruleVerdict(rules[0])
	assert.Equal(t, expr.VerdictAccept, v0)
	assert.True(t, ruleMatchesUID(rules[0], testVMUIDs.Envoy),
		"first postrouting rule should accept Envoy UID")

	v1, _ := ruleVerdict(rules[1])
	assert.Equal(t, expr.VerdictAccept, v1)
	assert.True(t, ruleMatchesUID(rules[1], testVMUIDs.Root),
		"second postrouting rule should accept root UID")

	// DROP rule should use matchHasSocketOwner (MetaKeySKUID with
	// CmpOpGte) so forwarded traffic (no socket) passes through.
	lastRule := rules[len(rules)-1]
	v, _ := ruleVerdict(lastRule)
	assert.Equal(t, expr.VerdictDrop, v)
	assert.True(t, ruleHasMetaKey(lastRule, expr.MetaKeySKUID),
		"VM mode postrouting DROP should use matchHasSocketOwner")

	// Verify CmpOpGte (matchHasSocketOwner) rather than CmpOpEq (matchUID).
	var hasCmpGte bool
	for _, e := range lastRule.Exprs {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpGte {
			hasCmpGte = true
		}
	}

	assert.True(t, hasCmpGte,
		"VM mode postrouting DROP should use CmpOpGte (matchHasSocketOwner), not CmpOpEq (matchUID)")

	// ICMP accept rules should exist between UID accepts and drop.
	var icmpAccept, icmpv6Accept bool
	for _, r := range rules {
		rv, _ := ruleVerdict(r)
		if rv != expr.VerdictAccept {
			continue
		}

		if ruleMatchesL4Proto(r, 1) { // IPPROTO_ICMP
			icmpAccept = true
		}

		if ruleMatchesL4Proto(r, 58) { // IPPROTO_ICMPV6
			icmpv6Accept = true
		}
	}

	assert.True(t, icmpAccept, "VM mode postrouting_guard should accept ICMP")
	assert.True(t, icmpv6Accept, "VM mode postrouting_guard should accept ICMPv6")
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

	// NAT: DNS REDIRECT with Envoy/Root ACCEPT before them.
	natRules := rec.rulesForChain("nat_output")
	require.NotEmpty(t, natRules, "blocked VM mode should have nat_output for DNS REDIRECT")

	// First two rules: Envoy ACCEPT, Root ACCEPT.
	require.GreaterOrEqual(t, len(natRules), 4)

	v, _ := ruleVerdict(natRules[0])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleMatchesUID(natRules[0], testVMUIDs.Envoy))

	v, _ = ruleVerdict(natRules[1])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleMatchesUID(natRules[1], testVMUIDs.Root))

	// Remaining rules: DNS REDIRECT (UDP + TCP).
	var vmRedirCount int
	for _, r := range natRules[2:] {
		if ruleHasRedir(r) {
			vmRedirCount++
		}
	}

	assert.Equal(t, 2, vmRedirCount, "should have DNS UDP and DNS TCP REDIRECTs")
}

func TestApplyRules_ExcludeUIDs(t *testing.T) {
	t.Parallel()

	const dnsmasqUID uint32 = 997

	tests := map[string]struct {
		uids firewall.UIDs
		cfg  *config.Config
	}{
		"container_unrestricted": {
			uids: firewall.UIDs{
				Terrarium:   1000,
				Envoy:       999,
				Root:        0,
				ExcludeUIDs: []uint32{dnsmasqUID},
			},
			cfg: &config.Config{},
		},
		"container_blocked": {
			uids: firewall.UIDs{
				Terrarium:   1000,
				Envoy:       999,
				Root:        0,
				ExcludeUIDs: []uint32{dnsmasqUID},
			},
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{}),
			},
		},
		"vm_unrestricted": {
			uids: firewall.UIDs{
				Envoy:       999,
				Root:        0,
				VMMode:      true,
				ExcludeUIDs: []uint32{dnsmasqUID},
			},
			cfg: &config.Config{},
		},
		"vm_blocked": {
			uids: firewall.UIDs{
				Envoy:       999,
				Root:        0,
				VMMode:      true,
				ExcludeUIDs: []uint32{dnsmasqUID},
			},
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{}),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tc.cfg, tc.uids)
			require.NoError(t, err)

			natRules := rec.rulesForChain("nat_output")
			require.NotEmpty(t, natRules)

			// Find the first excluded-UID ACCEPT and first DNS REDIRECT.
			firstExcludeAccept := -1
			firstDNSRedir := -1

			for i, r := range natRules {
				if firstExcludeAccept == -1 &&
					ruleMatchesUID(r, dnsmasqUID) &&
					ruleHasDstPort(r, 53) {
					v, _ := ruleVerdict(r)
					if v == expr.VerdictAccept {
						firstExcludeAccept = i
					}
				}

				if firstDNSRedir == -1 &&
					ruleHasRedir(r) &&
					ruleHasDstPort(r, 53) {
					firstDNSRedir = i
				}
			}

			require.NotEqual(t, -1, firstExcludeAccept,
				"should have ACCEPT rule for excluded UID on port 53")
			require.NotEqual(t, -1, firstDNSRedir,
				"should have DNS REDIRECT rule")
			assert.Less(t, firstExcludeAccept, firstDNSRedir,
				"excluded UID ACCEPT must come before DNS REDIRECT")

			// Both UDP and TCP should have ACCEPT rules for the
			// excluded UID.
			var excludeAcceptCount int
			for _, r := range natRules {
				if ruleMatchesUID(r, dnsmasqUID) && ruleHasDstPort(r, 53) {
					v, _ := ruleVerdict(r)
					if v == expr.VerdictAccept {
						excludeAcceptCount++
					}
				}
			}

			assert.Equal(t, 2, excludeAcceptCount,
				"should have ACCEPT rules for excluded UID on both UDP and TCP port 53")

			// The filter output chain must also allow excluded UID DNS
			// so their queries to external upstream resolvers are not
			// dropped by the chain policy.
			outputRules := rec.rulesForChain("output")
			require.NotEmpty(t, outputRules)

			var filterAcceptCount int
			for _, r := range outputRules {
				if ruleMatchesUID(r, dnsmasqUID) && ruleHasDstPort(r, 53) {
					v, _ := ruleVerdict(r)
					if v == expr.VerdictAccept {
						filterAcceptCount++
					}
				}
			}

			assert.Equal(t, 2, filterAcceptCount,
				"should have filter output ACCEPT rules for excluded UID on both UDP and TCP port 53")

			// VM mode (non-blocked): the postrouting_guard must also
			// allow excluded UID DNS so upstream queries can egress on
			// non-loopback. Blocked mode has no postrouting_guard since
			// the output chain drops all traffic.
			pgRules := rec.rulesForChain("postrouting_guard")
			if tc.uids.VMMode && len(pgRules) > 0 {
				var pgAcceptCount int
				for _, r := range pgRules {
					if ruleMatchesUID(r, dnsmasqUID) && ruleHasDstPort(r, 53) {
						v, _ := ruleVerdict(r)
						if v == expr.VerdictAccept {
							pgAcceptCount++
						}
					}
				}

				assert.Equal(t, 2, pgAcceptCount,
					"should have postrouting_guard ACCEPT rules for excluded UID on both UDP and TCP port 53")
			}
		})
	}
}

func TestApplyRules_VMMode_NATPreRouting(t *testing.T) {
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

	names := rec.chainNames()
	assert.Contains(t, names, "nat_prerouting")

	rules := rec.rulesForChain("nat_prerouting")
	require.NotEmpty(t, rules)

	// Should have DNS DNAT for UDP + TCP port 53. Non-DNS forwarded
	// TCP uses TPROXY in mangle PREROUTING; DNS TCP DNAT here catches
	// queries to bridge-local resolvers (e.g., BuildKit on the CNI
	// gateway) where mangle's matchNotLocalDst skips them.
	var dnsDNATCount int
	for _, r := range rules {
		if ruleHasNAT(r) && ruleHasDstPort(r, 53) {
			dnsDNATCount++
		}
	}

	assert.Equal(t, 2, dnsDNATCount, "should have DNS DNAT for UDP and TCP")

	// Bridge-local DNAT for resolved ports (port 443 in this config).
	var bridgeLocalDNATCount int
	for _, r := range rules {
		if ruleHasNAT(r) && !ruleHasDstPort(r, 53) {
			bridgeLocalDNATCount++
		}
	}

	assert.Equal(t, 1, bridgeLocalDNATCount,
		"should have bridge-local DNAT for resolved port 443")
}

func TestApplyRules_VMMode_NATPreRouting_Unrestricted(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "nat_prerouting")

	rules := rec.rulesForChain("nat_prerouting")
	require.NotEmpty(t, rules)

	// Should have DNS DNAT for UDP + TCP (2) plus bridge-local DNAT
	// for ports 80 and 443 (2) = 4 total.
	var natCount int
	for _, r := range rules {
		if ruleHasNAT(r) {
			natCount++
		}
	}

	assert.Equal(t, 4, natCount,
		"should have DNAT for DNS (UDP+TCP) and bridge-local (80+443)")
}

func TestApplyRules_VMMode_NATPreRouting_TCPForwards(t *testing.T) {
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
			{Port: 22, Host: "github.com"},
		},
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	rules := rec.rulesForChain("nat_prerouting")
	require.NotEmpty(t, rules)

	// 2 DNS (UDP+TCP) + 1 resolved port (443) + 1 TCPForward (22) = 4.
	var natCount int
	for _, r := range rules {
		if ruleHasNAT(r) {
			natCount++
		}
	}

	assert.Equal(t, 4, natCount,
		"should have DNAT for DNS, resolved port, and TCPForward")

	// Verify the TCPForward port is present.
	var hasTCPForwardPort bool
	for _, r := range rules {
		if ruleHasNAT(r) && ruleHasDstPort(r, 22) {
			hasTCPForwardPort = true
		}
	}

	assert.True(t, hasTCPForwardPort,
		"should have bridge-local DNAT for TCPForward port 22")
}

func TestApplyRules_VMMode_ForwardChain(t *testing.T) {
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

	names := rec.chainNames()
	assert.Contains(t, names, "forward")

	rules := rec.rulesForChain("forward")
	require.NotEmpty(t, rules)

	// First rule should be established/related ACCEPT.
	v, _ := ruleVerdict(rules[0])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleHasCtState(rules[0]),
		"first forward rule should match CT state")

	// Should have jump to terrarium_output.
	var hasJump bool
	for _, r := range rules {
		vk, chain := ruleVerdict(r)
		if vk == expr.VerdictJump && chain == "terrarium_output" {
			hasJump = true
		}
	}

	assert.True(t, hasJump,
		"forward chain should jump to terrarium_output for policy evaluation")
}

func TestApplyRules_VMMode_ForwardChain_Unrestricted(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "forward")

	rules := rec.rulesForChain("forward")
	require.NotEmpty(t, rules)

	// Should end with unconditional ACCEPT.
	lastV, _ := ruleVerdict(rules[len(rules)-1])
	assert.Equal(t, expr.VerdictAccept, lastV)
}

func TestApplyRules_VMMode_ForwardChain_Blocked(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{}),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	names := rec.chainNames()
	assert.Contains(t, names, "forward")

	rules := rec.rulesForChain("forward")
	require.NotEmpty(t, rules)

	// Should have established ACCEPT but no jump to terrarium_output.
	v, _ := ruleVerdict(rules[0])
	assert.Equal(t, expr.VerdictAccept, v)
	assert.True(t, ruleHasCtState(rules[0]))

	// No jump to terrarium_output (all new traffic dropped by policy).
	for _, r := range rules {
		vk, chain := ruleVerdict(r)
		assert.False(t, vk == expr.VerdictJump && chain == "terrarium_output",
			"blocked mode forward chain should not jump to terrarium_output")
	}
}

func TestApplyRules_VMMode_MangleForwarded(t *testing.T) {
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

	rules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, rules)

	// First rule should accept established/related forwarded traffic
	// to prevent TPROXY from intercepting return traffic.
	firstRule := rules[0]
	v, _ := ruleVerdict(firstRule)
	assert.Equal(t, expr.VerdictAccept, v,
		"first mangle_prerouting rule should accept established/related")

	// Should have marking rules (fwmark but no TPROXY) followed
	// by TPROXY dispatch rules.
	var hasMark, hasTProxy bool
	for _, r := range rules[1:] {
		if ruleHasMark(r) && !ruleHasTProxy(r) {
			hasMark = true
		}

		if ruleHasTProxy(r) {
			hasTProxy = true
		}
	}

	assert.True(t, hasMark, "should have forwarded marking rules")
	assert.True(t, hasTProxy, "should have TPROXY rules after forwarded marking")
}

// ruleHasNAT reports whether a rule contains a NAT expression.
func ruleHasNAT(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.NAT); ok {
			return true
		}
	}

	return false
}

// ruleHasDstPort reports whether a rule matches the given destination port.
func ruleHasDstPort(r *nftables.Rule, port uint16) bool {
	expected := binaryutil.BigEndian.PutUint16(port)

	for i, e := range r.Exprs {
		p, ok := e.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader || p.Offset != 2 {
			continue
		}

		if i+1 >= len(r.Exprs) {
			continue
		}

		c, ok := r.Exprs[i+1].(*expr.Cmp)
		if ok && c.Op == expr.CmpOpEq && assert.ObjectsAreEqual(expected, c.Data) {
			return true
		}
	}

	return false
}

// ruleMatchesNFProto reports whether a rule matches a specific
// nfproto (address family) value.
func ruleMatchesNFProto(r *nftables.Rule, proto byte) bool {
	hasNFProto := false

	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyNFPROTO {
			hasNFProto = true
		}

		if hasNFProto {
			if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq {
				if len(c.Data) == 1 && c.Data[0] == proto {
					return true
				}
			}
		}
	}

	return false
}

// ruleMatchesL4Proto reports whether a rule matches a specific
// L4 protocol value.
func ruleMatchesL4Proto(r *nftables.Rule, proto byte) bool {
	hasL4Proto := false

	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyL4PROTO {
			hasL4Proto = true
		}

		if hasL4Proto {
			if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq {
				if len(c.Data) == 1 && c.Data[0] == proto {
					return true
				}
			}
		}
	}

	return false
}

func TestApplyRules_VMMode_IPv6TPROXY(t *testing.T) {
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

	rules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, rules)

	// Count marking rules (have mark set but no TPROXY).
	var markRules []*nftables.Rule
	for _, r := range rules {
		if ruleHasMark(r) && !ruleHasTProxy(r) {
			markRules = append(markRules, r)
		}
	}

	// Should have 4 marking rules: IPv4 UDP, IPv6 UDP, IPv4 TCP, IPv6 TCP.
	require.Len(t, markRules, 4,
		"VM mode should have 4 marking rules (IPv4 UDP, IPv6 UDP, IPv4 TCP, IPv6 TCP)")

	// First marking rule: IPv4 forwarded UDP (excludes DNS port 53).
	assert.True(t, ruleMatchesNFProto(markRules[0], 2),
		"first mark rule should be IPv4")
	assert.True(t, ruleMatchesL4Proto(markRules[0], 17),
		"first mark rule should be UDP")

	// Second marking rule: IPv6 forwarded UDP (includes DNS).
	assert.True(t, ruleMatchesNFProto(markRules[1], 10),
		"second mark rule should be IPv6")
	assert.True(t, ruleMatchesL4Proto(markRules[1], 17),
		"second mark rule should be UDP")

	// Third marking rule: IPv4 forwarded TCP.
	assert.True(t, ruleMatchesNFProto(markRules[2], 2),
		"third mark rule should be IPv4")
	assert.True(t, ruleMatchesL4Proto(markRules[2], 6),
		"third mark rule should be TCP")

	// Fourth marking rule: IPv6 forwarded TCP.
	assert.True(t, ruleMatchesNFProto(markRules[3], 10),
		"fourth mark rule should be IPv6")
	assert.True(t, ruleMatchesL4Proto(markRules[3], 6),
		"fourth mark rule should be TCP")

	// Should have IPv6 TPROXY dispatch rules.
	var ipv6TProxyCount int
	for _, r := range rules {
		if ruleHasTProxy(r) && ruleMatchesNFProto(r, 10) {
			ipv6TProxyCount++
		}
	}

	// At least: 2 DNS (UDP+TCP), 1 per-port 443, 1 catch-all TCP,
	// plus the generic IPv6 UDP TPROXY.
	assert.GreaterOrEqual(t, ipv6TProxyCount, 4,
		"should have IPv6 TPROXY dispatch rules for DNS, per-port, and catch-all")
}

func TestApplyRules_VMMode_IPv6TPROXY_NotInContainerMode(t *testing.T) {
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

	rules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, rules)

	// Container mode: only 2 TPROXY rules (IPv4 UDP, IPv6 UDP).
	var tproxyCount int
	for _, r := range rules {
		if ruleHasTProxy(r) {
			tproxyCount++
		}
	}

	assert.Equal(t, 2, tproxyCount,
		"container mode should only have IPv4+IPv6 UDP TPROXY rules")

	// No marking rules in container mode (no forwarded traffic).
	for _, r := range rules {
		if ruleHasMark(r) && !ruleHasTProxy(r) {
			t.Error("container mode should not have marking rules in mangle_prerouting")
		}
	}
}

func TestApplyRules_VMMode_IPv6TPROXY_DenyCIDR(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	denyRules := []config.EgressDenyRule{{
		ToCIDRSet: []config.CIDRRule{{CIDR: "2001:db8::/32", Except: []string{"2001:db8:1::/48"}}},
	}}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
		EgressDeny: &denyRules,
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	// Should have a deny_cidr_tproxy6 chain with per-rule structure.
	names := rec.chainNames()
	assert.Contains(t, names, "deny_cidr_tproxy6_0",
		"should create per-rule deny CIDR TPROXY chain")

	chainRules := rec.rulesForChain("deny_cidr_tproxy6_0")
	require.NotEmpty(t, chainRules)

	// Chain should have except RETURN before CIDR ACCEPT.
	var hasReturn, hasAccept bool

	returnIdx, acceptIdx := -1, -1

	for i, r := range chainRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictReturn && !hasReturn {
			hasReturn = true
			returnIdx = i
		}

		if v == expr.VerdictAccept && !hasAccept {
			hasAccept = true
			acceptIdx = i
		}
	}

	assert.True(t, hasReturn, "deny CIDR TPROXY chain should have except RETURN")
	assert.True(t, hasAccept, "deny CIDR TPROXY chain should have CIDR ACCEPT")
	assert.Less(t, returnIdx, acceptIdx,
		"except RETURN should come before CIDR ACCEPT")
}

func TestApplyRules_VMMode_IPv6TPROXY_AllowCIDR(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToCIDR:    []string{"2001:db8::/32"},
				ToCIDRSet: []config.CIDRRule{{CIDR: "2001:db8::/32", Except: []string{"2001:db8:1::/48"}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	// Should have a cidr_tproxy6 chain with per-rule structure.
	// CIDR chains clear the TPROXY mark and accept, letting the
	// packet be forwarded directly (the FORWARD chain enforces
	// the CIDR allowlist).
	names := rec.chainNames()
	assert.Contains(t, names, "cidr_tproxy6_0",
		"should create per-rule allow CIDR chain")

	cidrRules := rec.rulesForChain("cidr_tproxy6_0")
	require.NotEmpty(t, cidrRules)

	// Chain should have except RETURN before mark-clear + accept.
	var hasReturn, hasAccept bool

	for _, r := range cidrRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictReturn {
			hasReturn = true
		}

		if v == expr.VerdictAccept {
			hasAccept = true
		}
	}

	assert.True(t, hasReturn, "allow CIDR chain should have except RETURN")
	assert.True(t, hasAccept, "allow CIDR chain should have mark-clear + accept")
}

func TestApplyRules_VMMode_Unrestricted_IPv6TPROXY(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{} // nil Egress = unrestricted

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	rules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, rules)

	// VM unrestricted mode should have IPv6 marking and TPROXY dispatch.
	var (
		ipv6TCPMarkCount int
		ipv6UDPMarkCount int
		ipv6TCPTProxy    int
		ipv6DNSTProxy    int
	)

	for _, r := range rules {
		isMark := ruleHasMark(r) && !ruleHasTProxy(r)
		isIPv6 := ruleMatchesNFProto(r, 10) // NFPROTO_IPV6

		if isMark && isIPv6 && ruleMatchesL4Proto(r, 6) {
			ipv6TCPMarkCount++
		}

		if isMark && isIPv6 && ruleMatchesL4Proto(r, 17) {
			ipv6UDPMarkCount++
		}

		if ruleHasTProxy(r) && isIPv6 && ruleMatchesL4Proto(r, 6) {
			ipv6TCPTProxy++
		}

		if ruleHasTProxy(r) && isIPv6 && ruleHasDstPort(r, 53) {
			ipv6DNSTProxy++
		}
	}

	assert.Equal(t, 1, ipv6TCPMarkCount,
		"unrestricted VM mode should mark IPv6 forwarded TCP")
	assert.Equal(t, 1, ipv6UDPMarkCount,
		"unrestricted VM mode should mark IPv6 forwarded UDP")
	assert.GreaterOrEqual(t, ipv6TCPTProxy, 3,
		"unrestricted VM mode should have IPv6 TCP TPROXY dispatch (80, 443, catch-all)")
	assert.GreaterOrEqual(t, ipv6DNSTProxy, 1,
		"unrestricted VM mode should have IPv6 DNS TPROXY dispatch")
}

// ruleWritesMark reports whether a rule contains a Meta expression that
// writes the fwmark (SourceRegister: true with MetaKeyMARK).
func ruleWritesMark(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyMARK && m.SourceRegister {
			return true
		}
	}

	return false
}

// ruleHasBitwise reports whether a rule contains a Bitwise expression.
func ruleHasBitwise(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if _, ok := e.(*expr.Bitwise); ok {
			return true
		}
	}

	return false
}

func TestOutputChain_GuardMark(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		uids firewall.UIDs
		// Guard mark is always the first rule (index 0) in the output
		// chain across all modes.
		wantIndex int
	}{
		"unrestricted": {
			cfg:       &config.Config{},
			uids:      testUIDs,
			wantIndex: 0,
		},
		"blocked": {
			cfg:       &config.Config{Egress: egressRules(config.EgressRule{})},
			uids:      testUIDs,
			wantIndex: 0,
		},
		"filtered": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
				),
			},
			uids:      testUIDs,
			wantIndex: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tc.cfg, tc.uids)
			require.NoError(t, err)

			outputRules := rec.rulesForChain("output")
			require.Greater(t, len(outputRules), tc.wantIndex,
				"output chain should have enough rules for guard mark")

			guardRule := outputRules[tc.wantIndex]
			assert.True(t, ruleWritesMark(guardRule),
				"rule at index %d should write the guard mark", tc.wantIndex)
		})
	}
}

func TestMatchMark_Bitmask(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}
	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToCIDR: []string{"10.0.0.0/8"},
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443", Protocol: "TCP"},
				}}},
			},
		),
	}

	err := firewall.ApplyRules(t.Context(), rec, cfg, testVMUIDs)
	require.NoError(t, err)

	// Verify bitmask matching is used in mangle_prerouting for TPROXY
	// mark rules. TPROXY rules should use Bitwise for bitmask matching,
	// not exact equality.
	mangleRules := rec.rulesForChain("mangle_prerouting")
	require.NotEmpty(t, mangleRules)

	var foundBitmaskMark bool

	for _, r := range mangleRules {
		if !ruleHasMark(r) {
			continue
		}

		// Should use Bitwise for bitmask matching.
		if ruleHasBitwise(r) {
			foundBitmaskMark = true
		}
	}

	assert.True(t, foundBitmaskMark,
		"mangle_prerouting chain should have a bitmask mark match rule")
}
