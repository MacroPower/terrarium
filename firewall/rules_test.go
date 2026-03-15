package firewall_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall"
)

var testUIDs = firewall.UIDs{Sandbox: 1000, Envoy: 999, Root: 0}

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

	// Chains: input, output (no sandbox_output, no nat_output).
	names := rec.chainNames()
	assert.Contains(t, names, "input")
	assert.Contains(t, names, "output")
	assert.NotContains(t, names, "sandbox_output")

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
	require.Len(t, natRules, 1)
	assert.True(t, ruleHasRedir(natRules[0]))
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
	assert.NotContains(t, names, "sandbox_output")
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
	assert.Contains(t, names, "sandbox_output")
	assert.Contains(t, names, "cidr_0")
	assert.Contains(t, names, "nat_output")

	// OUTPUT chain: verify UID 1000 dispatch to sandbox_output
	// appears before ESTABLISHED.
	outputRules := rec.rulesForChain("output")

	var jumpIdx, estIdx int
	for i, r := range outputRules {
		v, chain := ruleVerdict(r)
		if v == expr.VerdictJump && chain == "sandbox_output" {
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

	// sandbox_output ends with DROP.
	sandboxRules := rec.rulesForChain("sandbox_output")
	require.NotEmpty(t, sandboxRules)

	v, _ = ruleVerdict(sandboxRules[len(sandboxRules)-1])
	assert.Equal(t, expr.VerdictDrop, v)

	// sandbox_output has jump to cidr_0.
	var hasCIDRJump bool
	for _, r := range sandboxRules {
		vk, chain := ruleVerdict(r)
		if vk == expr.VerdictJump && chain == "cidr_0" {
			hasCIDRJump = true
			break
		}
	}

	assert.True(t, hasCIDRJump, "sandbox_output must jump to cidr_0")

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

	assert.Equal(t, 3, redirCount, "should have REDIRECTs for ports 80, 443, 8080")

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

	// Logging: sandbox_output has LOG before DROP.
	assert.True(t, ruleHasLog(sandboxRules[len(sandboxRules)-2]))
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
	// after the UID 1000 dispatch and before ESTABLISHED. Only UID
	// 1000 enters sandbox_output, so the Envoy rule must live in
	// the output chain for Envoy's outbound connections to pass.
	sandboxJumpIdx, envoyIdx, estIdx := -1, -1, -1
	for i, r := range outputRules {
		vk, chain := ruleVerdict(r)
		if vk == expr.VerdictJump && chain == "sandbox_output" {
			sandboxJumpIdx = i
		}

		if envoyIdx == -1 && vk == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			envoyIdx = i
		}

		if ruleHasCtState(r) && vk == expr.VerdictAccept && !ruleHasMetaKey(r, expr.MetaKeySKUID) {
			estIdx = i
			break
		}
	}

	require.NotEqual(t, -1, sandboxJumpIdx, "sandbox_output jump must exist")
	require.NotEqual(t, -1, envoyIdx, "Envoy ACCEPT must exist in output chain")
	require.NotEqual(t, -1, estIdx, "ESTABLISHED ACCEPT must exist")

	assert.Greater(t, envoyIdx, sandboxJumpIdx,
		"Envoy ACCEPT must come after UID 1000 dispatch")
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
	assert.Contains(t, setNames, "sandbox_fqdn4_0")
	assert.Contains(t, setNames, "sandbox_fqdn6_0")

	// Sets have correct key types.
	for _, s := range rec.sets {
		if s.Name == "sandbox_fqdn4_0" {
			assert.Equal(t, nftables.TypeIPAddr, s.KeyType)
			assert.True(t, s.HasTimeout)
		}

		if s.Name == "sandbox_fqdn6_0" {
			assert.Equal(t, nftables.TypeIP6Addr, s.KeyType)
			assert.True(t, s.HasTimeout)
		}
	}

	// sandbox_output has FQDN set lookup rules.
	sandboxRules := rec.rulesForChain("sandbox_output")

	var lookupCount int
	for _, r := range sandboxRules {
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

	sandboxRules := rec.rulesForChain("sandbox_output")

	// Find ESTABLISHED and Lookup rule positions for FQDN port.
	estIdx, lookupIdx := -1, -1
	for i, r := range sandboxRules {
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

	// sandbox_output has blanket UID 1000 ACCEPT.
	sandboxRules := rec.rulesForChain("sandbox_output")

	var hasBlanketAccept bool
	for _, r := range sandboxRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			hasBlanketAccept = true
		}
	}

	assert.True(t, hasBlanketAccept,
		"unrestricted open ports should have blanket UID 1000 ACCEPT")
}

func TestApplyRules_OpenTCPSinglePortNATOptimization(t *testing.T) {
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

	// NAT should have RETURN for port 443 before REDIRECT.
	natRules := rec.rulesForChain("nat_output")

	returnIdx, redirIdx := -1, -1
	for i, r := range natRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictReturn && returnIdx == -1 {
			returnIdx = i
		}

		if ruleHasRedir(r) && redirIdx == -1 {
			redirIdx = i
		}
	}

	require.NotEqual(t, -1, returnIdx, "should have NAT RETURN for open TCP port")
	require.NotEqual(t, -1, redirIdx, "should have NAT REDIRECT")
	assert.Less(t, returnIdx, redirIdx,
		"open TCP port RETURN must precede REDIRECT")
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
	assert.Contains(t, setNames, "sandbox_fqdn4_0")
	assert.Contains(t, setNames, "sandbox_fqdn6_0")
	assert.Contains(t, setNames, "sandbox_fqdn4_1")
	assert.Contains(t, setNames, "sandbox_fqdn6_1")
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

	sandboxRules := rec.rulesForChain("sandbox_output")

	// Count ACCEPT rules that have UID matching (open port rules).
	var acceptCount int
	for _, r := range sandboxRules {
		v, _ := ruleVerdict(r)
		if v == expr.VerdictAccept && ruleHasMetaKey(r, expr.MetaKeySKUID) {
			acceptCount++
		}
	}

	// Should have: UDP open port ACCEPT + TCP range ACCEPT = 2.
	// Envoy ACCEPT is in the output chain, not sandbox_output.
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

	// Both get jumped from sandbox_output.
	sandboxRules := rec.rulesForChain("sandbox_output")

	var jumpChains []string
	for _, r := range sandboxRules {
		v, chain := ruleVerdict(r)
		if v == expr.VerdictJump {
			jumpChains = append(jumpChains, chain)
		}
	}

	assert.Contains(t, jumpChains, "cidr_0")
	assert.Contains(t, jumpChains, "cidr_1")
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
