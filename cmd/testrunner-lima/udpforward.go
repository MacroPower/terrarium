package main

import (
	"context"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "embed"
)

const (
	// The path of [udpForwardScript] in the VM.
	udpForwardScriptPath = "/tmp/udp-forward.sh"

	// The time limit of the removal of the network that
	// [udpForwardScript] builds.
	udpForwardCleanupTimeout = 30 * time.Second
)

var (
	// The shell script that [verifyForwardedUDPPolicy] runs in the VM.
	// The script sends forwarded UDP from network namespaces on a
	// bridge and counts where each datagram arrives. Its header comment
	// describes the network and names each counter.
	//
	//go:embed udp_forward.sh
	udpForwardScript string

	// Matches one nftables rule that has a counter and a comment in
	// the output of "nft list table".
	ruleCounter = regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "([a-z0-9_]+)"`)
)

// parseRuleCounters returns the packet count of each nftables rule in
// listing that has a counter and a comment. The comment of the rule is
// the key of its count.
func parseRuleCounters(listing string) map[string]uint64 {
	counters := make(map[string]uint64)

	for _, match := range ruleCounter.FindAllStringSubmatch(listing, -1) {
		packets, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			continue
		}

		counters[match[2]] = packets
	}

	return counters
}

// verifyForwardedUDPPolicy checks that the egress policy decides the
// forwarded UDP of bridge-attached containers. It is the verify hook
// of the vm-container-udp-policy case. The policy of that case allows
// two UDP ports of the service subnets, and a port-only egressDeny
// rule denies the second one again. The allowlist names the denied
// port so that only the egressDeny rule can drop its datagrams. The
// policy also names the uplink of the bridge in bridgeUplinks.
//
// Network namespaces stand in for the containers, because the case
// needs a client on a TAP port and IPv6 addresses. The container
// networks of the VM are IPv4 networks with veth ports. One client is
// on a veth port of the bridge and one client is on a TAP port. The VM
// routes their datagrams to a service namespace on another subnet. The
// script turns on IPv6 forwarding in the VM for the duration of the
// case, because the VM forwards only IPv4 by default. See
// [udpForwardScript].
//
// For each client and each address family, the hook checks that:
//
//   - The datagrams of the allowed port pass the policy and arrive at
//     the transparent listener of Envoy from the bridge port.
//   - The datagrams of the port of the egressDeny rule do not pass the
//     policy and do not arrive at the service.
//   - The datagrams of a port that no rule names do not pass the
//     policy and do not arrive at the service.
//
// The hook also checks that a datagram from the uplink to the bridge
// keeps the bridge as its input interface.
//
// The hook does not check that the datagrams of the allowed port
// arrive at the service. Envoy drops every UDP datagram that TPROXY
// delivers to its listener, so no datagram of a forwarded flow
// arrives at its destination. The check of the allowed port therefore
// ends at the listener.
func verifyForwardedUDPPolicy(ctx context.Context, t *testing.T, d *driver) {
	t.Helper()

	err := d.writeFile(ctx, udpForwardScriptPath, udpForwardScript)
	require.NoError(t, err)

	// The caller cancels ctx before the cleanup functions of the
	// test run, so the cleanup needs a context of its own.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), udpForwardCleanupTimeout)
		defer cancel()

		_, err := d.shell(cleanupCtx, "sudo", "sh", udpForwardScriptPath, "down")
		if err != nil {
			t.Logf("cleanup: removing the forwarded UDP network: %v", err)
		}
	})

	out, err := d.shell(ctx, "sudo", "sh", udpForwardScriptPath, "up")
	require.NoError(t, err, "building the forwarded UDP network: %s", out)

	out, err = d.shell(ctx, "sudo", "sh", udpForwardScriptPath, "send")
	require.NoError(t, err, "sending the datagrams: %s", out)

	report, err := d.shell(ctx, "sudo", "sh", udpForwardScriptPath, "report")
	require.NoError(t, err, "reading the counters: %s", report)

	counters := parseRuleCounters(report)

	count := func(name string) uint64 {
		t.Helper()

		packets, ok := counters[name]
		require.Truef(t, ok, "the report holds no counter %q\n%s", name, report)

		return packets
	}

	for _, family := range []string{"4", "6"} {
		for _, client := range []string{"veth", "tap"} {
			flow := client + "_" + family

			// A datagram that never arrived in the VM passes no
			// policy. So each check of a dropped port needs proof
			// that the datagrams of the port arrived.
			for _, role := range []string{"allow", "deny", "unlisted"} {
				assert.Positivef(t, count("sent_"+flow+"_"+role),
					"%s client, IPv%s: no datagram of the %s port arrived in the VM",
					client, family, role)
			}

			assert.Positivef(t, count("passed_"+flow+"_allow"),
				"%s client, IPv%s: the policy dropped the allowed port", client, family)
			assert.Positivef(t, count("proxy_"+flow),
				"%s client, IPv%s: no datagram of the allowed port arrived at the listener of Envoy",
				client, family)
			assert.Zerof(t, count("passed_"+flow+"_deny"),
				"%s client, IPv%s: the policy accepted the port of the egressDeny rule",
				client, family)
			assert.Zerof(t, count("passed_"+flow+"_unlisted"),
				"%s client, IPv%s: the policy accepted a port that no rule allows",
				client, family)
		}

		assert.Zerof(t, count("service_"+family+"_deny"),
			"IPv%s: the service received the port of the egressDeny rule", family)
		assert.Zerof(t, count("service_"+family+"_unlisted"),
			"IPv%s: the service received a port that no rule allows", family)

		assert.Positivef(t, count("uplink_bridge_"+family),
			"IPv%s: no uplink datagram arrived with the bridge as its input interface", family)
		assert.Zerof(t, count("uplink_port_"+family),
			"IPv%s: an uplink datagram arrived with the uplink port as its input interface", family)
	}

	if !t.Failed() {
		return
	}

	// Collect diagnostics on failure.
	inet, inetErr := d.shell(ctx, "sudo", "nft", "list", "table", "inet", "terrarium")
	bridge, bridgeErr := d.shell(ctx, "sudo", "nft", "list", "table", "bridge", "terrarium")
	links, linksErr := d.shell(ctx, "ip", "-d", "link", "show")
	ipRules, ipRulesErr := d.shell(ctx, "ip", "rule", "show")

	for name, derr := range map[string]error{
		"nft inet": inetErr, "nft bridge": bridgeErr, "links": linksErr, "routing rules": ipRulesErr,
	} {
		if derr != nil {
			t.Logf("diagnostic %s: %v", name, derr)
		}
	}

	t.Logf("forwarded UDP counters:\n%s\n\nnft inet terrarium:\n%s"+
		"\nnft bridge terrarium:\n%s\nip link:\n%s\nip rule:\n%s",
		report, inet, bridge, links, ipRules)
}
