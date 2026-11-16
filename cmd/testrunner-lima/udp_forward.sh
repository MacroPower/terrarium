#!/bin/sh
# Sends forwarded UDP through the firewall of the VM and counts where
# each datagram arrives. The vm-container-udp-policy case runs this
# script in the VM as root.
#
# Usage: udp_forward.sh up|send|report|down
#
#   up      Builds the network and the counters, and turns on IPv6
#           forwarding.
#   send    Sends the datagrams.
#   report  Prints the counters.
#   down    Removes the network and the counters, and restores IPv6
#           forwarding.
#
# The network holds one bridge, tudp-br, and four network namespaces.
# Two namespaces stand in for containers of the bridge:
#
#   - tudp-veth is on the veth port tudp-v0, the kind of port that a
#     container runtime creates.
#   - tudp-tap is on the TAP port tudp-t0, the kind of port that a
#     runtime creates for a container in a virtual machine. socat
#     holds tudp-t0 and a second TAP device, and it copies each frame
#     from one device to the other. The second device is the interface
#     of the namespace.
#
# The namespace tudp-uplink is on the veth port tudp-up, which the
# policy names in bridgeUplinks. The namespace tudp-svc holds the
# addresses of the service. It is on a link of its own, outside the
# subnets of the bridge, so the VM routes each datagram of a client.
#
# The VM forwards only IPv4 by default, so "up" turns on IPv6
# forwarding and "down" restores the setting that "up" found.
#
# Each client sends datagrams to three ports of the service over IPv4
# and over IPv6. The role of a port names what the policy does with
# the port. The egress rule of the policy allows the ports "allow"
# and "deny", and an egressDeny rule denies the port "deny" again. The
# egress rule names the port "deny" so that only the egressDeny rule
# can drop its datagrams. No rule names the port "unlisted". The
# uplink namespace sends datagrams to the addresses of the bridge.
#
# One nftables rule with a counter and a comment counts each kind of
# datagram. The comment is the name of the counter:
#
#   sent_CLIENT_FAMILY_ROLE   Datagrams that arrived in the VM,
#                             counted before the inet rules of
#                             terrarium.
#   passed_CLIENT_FAMILY_ROLE Datagrams that the policy accepted,
#                             counted after the INPUT chains.
#   proxy_CLIENT_FAMILY       Accepted datagrams of the allowed port
#                             that arrived on the bridge port and hold
#                             a transparent socket, which is the
#                             listener of Envoy.
#   uplink_bridge_FAMILY      Uplink datagrams whose input interface
#                             is the bridge.
#   uplink_port_FAMILY        Uplink datagrams whose input interface
#                             is the uplink port.
#   service_FAMILY_ROLE       Datagrams that arrived in the service
#                             namespace.
#
# CLIENT is "veth" or "tap", and FAMILY is "4" or "6".
set -eu

BRIDGE=tudp-br
BRIDGE_MAC=02:74:75:64:70:01
VETH_PORT=tudp-v0
TAP_PORT=tudp-t0
UPLINK=tudp-up
SERVICE_LINK=tudp-s0
SERVICE_MAC=02:74:75:64:70:02
SOCAT_PID=/run/tudp-socat.pid

# Holds the IPv6 forwarding setting that "up" found.
IPV6_FORWARDING=/run/tudp-ipv6-forwarding

# The ports of the policy in the vm-container-udp-policy case.
PORT_ALLOW=7001
PORT_DENY=7002
PORT_UNLISTED=7003

# The uplink namespace sends to this port of the bridge.
PORT_UPLINK=7004

# The first three groups of each subnet. The policy allows the
# service subnets.
BRIDGE4=10.210.0
BRIDGE6=fd00:d2:
SERVICE4=10.211.0
SERVICE6=fd00:d3:

down() {
	if [ -f "$SOCAT_PID" ]; then
		kill "$(cat "$SOCAT_PID")" 2>/dev/null || true
		rm -f "$SOCAT_PID"
	fi

	nft delete table inet tudp 2>/dev/null || true

	for link in "$VETH_PORT" "$UPLINK" "$SERVICE_LINK" "$BRIDGE"; do
		ip link del "$link" 2>/dev/null || true
	done

	for ns in tudp-veth tudp-tap tudp-uplink tudp-svc; do
		ip netns del "$ns" 2>/dev/null || true
	done

	if [ -f "$IPV6_FORWARDING" ]; then
		if sysctl -qw net.ipv6.conf.all.forwarding="$(cat "$IPV6_FORWARDING")"; then
			rm -f "$IPV6_FORWARDING"
		fi
	fi
}

# address NAMESPACE DEVICE IPV4_SUBNET IPV6_SUBNET HOST gives the
# device of the namespace the host address of both subnets. It routes
# every other destination through host 1 of the subnets.
address() {
	ip netns exec "$1" sh -c "
		set -e
		ip link set lo up
		ip addr add $3.$5/24 dev $2
		ip -6 addr add $4:$5/64 dev $2 nodad
		ip link set $2 up
		ip route add default via $3.1
		ip -6 route add default via $4:1
	"
}

# client_rules CHAIN CLIENT HOST prints one counter rule for each
# address family and each service port of the client.
client_rules() {
	for role in "allow:$PORT_ALLOW" "deny:$PORT_DENY" "unlisted:$PORT_UNLISTED"; do
		port=${role#*:}
		role=${role%:*}
		echo "ip saddr $BRIDGE4.$3 udp dport $port counter comment \"$1_$2_4_$role\""
		echo "ip6 saddr $BRIDGE6:$3 udp dport $port counter comment \"$1_$2_6_$role\""
	done
}

# proxy_rules CLIENT HOST PORT_DEVICE prints one counter rule for each
# address family of the client.
proxy_rules() {
	echo "iifname \"$3\" ip saddr $BRIDGE4.$2 udp dport $PORT_ALLOW socket transparent 1 counter comment \"proxy_$1_4\""
	echo "iifname \"$3\" ip6 saddr $BRIDGE6:$2 udp dport $PORT_ALLOW socket transparent 1 counter comment \"proxy_$1_6\""
}

# uplink_rules NAME DEVICE prints one counter rule for each address
# family of the uplink namespace.
uplink_rules() {
	echo "iifname \"$2\" ip saddr $BRIDGE4.4 udp dport $PORT_UPLINK counter comment \"uplink_$1_4\""
	echo "iifname \"$2\" ip6 saddr $BRIDGE6:4 udp dport $PORT_UPLINK counter comment \"uplink_$1_6\""
}

up() {
	down

	for ns in tudp-veth tudp-tap tudp-uplink tudp-svc; do
		ip netns add "$ns"
	done

	# A bridge takes the lowest MAC address of its ports unless it
	# has an address of its own. A fixed address keeps the neighbor
	# entries of the clients valid when a port joins the bridge.
	ip link add "$BRIDGE" address "$BRIDGE_MAC" type bridge stp_state 0 mcast_snooping 0
	ip addr add "$BRIDGE4.1/24" dev "$BRIDGE"
	ip -6 addr add "$BRIDGE6:1/64" dev "$BRIDGE" nodad
	ip link set "$BRIDGE" up

	ip link add "$VETH_PORT" type veth peer name tudp-v1 netns tudp-veth
	ip link set "$VETH_PORT" master "$BRIDGE" up
	address tudp-veth tudp-v1 "$BRIDGE4" "$BRIDGE6" 2

	# The TAP devices exist only while socat runs.
	nohup socat \
		"TUN,tun-type=tap,tun-name=$TAP_PORT,iff-no-pi" \
		TUN,tun-type=tap,tun-name=tudp-t1,iff-no-pi \
		>/dev/null 2>&1 </dev/null &
	echo $! >"$SOCAT_PID"

	tries=0
	until ip link show tudp-t1 >/dev/null 2>&1; do
		tries=$((tries + 1))

		if [ "$tries" -ge 50 ]; then
			echo "socat did not create the TAP devices" >&2
			exit 1
		fi

		sleep 0.1
	done

	ip link set "$TAP_PORT" master "$BRIDGE" up
	ip link set tudp-t1 netns tudp-tap
	address tudp-tap tudp-t1 "$BRIDGE4" "$BRIDGE6" 3

	ip link add "$UPLINK" type veth peer name tudp-up1 netns tudp-uplink
	ip link set "$UPLINK" master "$BRIDGE" up
	address tudp-uplink tudp-up1 "$BRIDGE4" "$BRIDGE6" 4

	# The kernel drops each forwarded IPv6 packet while IPv6
	# forwarding is off. When "down" did not restore the setting, the
	# file still holds the setting that the first "up" found.
	if [ ! -f "$IPV6_FORWARDING" ]; then
		sysctl -n net.ipv6.conf.all.forwarding >"$IPV6_FORWARDING"
	fi

	sysctl -qw net.ipv6.conf.all.forwarding=1

	ip link add "$SERVICE_LINK" type veth peer name tudp-s1 address "$SERVICE_MAC" netns tudp-svc
	ip addr add "$SERVICE4.1/24" dev "$SERVICE_LINK"
	ip -6 addr add "$SERVICE6:1/64" dev "$SERVICE_LINK" nodad
	ip link set "$SERVICE_LINK" up
	address tudp-svc tudp-s1 "$SERVICE4" "$SERVICE6" 2

	# Without a neighbor entry, the VM queues each forwarded datagram
	# until neighbor discovery finds the service, and "report" can
	# read the counters of the service before the datagrams arrive.
	ip neigh replace "$SERVICE4.2" lladdr "$SERVICE_MAC" dev "$SERVICE_LINK" nud permanent
	ip -6 neigh replace "$SERVICE6:2" lladdr "$SERVICE_MAC" dev "$SERVICE_LINK" nud permanent

	# The sent chain runs before each inet prerouting chain of
	# terrarium, and after the bridge prerouting chain. The bridge
	# chain decides only whether the packet leaves the bridge.
	# The passed chain runs after each INPUT chain of terrarium and
	# of the host firewall, so it counts only the datagrams that
	# those chains accepted.
	{
		echo "table inet tudp {"
		echo "chain sent { type filter hook prerouting priority raw; policy accept;"
		client_rules sent veth 2
		client_rules sent tap 3
		uplink_rules bridge "$BRIDGE"
		uplink_rules port "$UPLINK"
		echo "}"
		echo "chain passed { type filter hook input priority 10; policy accept;"
		client_rules passed veth 2
		client_rules passed tap 3
		proxy_rules veth 2 "$VETH_PORT"
		proxy_rules tap 3 "$TAP_PORT"
		echo "}"
		echo "}"
	} | nft -f -

	{
		echo "table inet tudp {"
		echo "chain service { type filter hook prerouting priority filter; policy accept;"

		for role in "allow:$PORT_ALLOW" "deny:$PORT_DENY" "unlisted:$PORT_UNLISTED"; do
			echo "meta nfproto ipv4 udp dport ${role#*:} counter comment \"service_4_${role%:*}\""
			echo "meta nfproto ipv6 udp dport ${role#*:} counter comment \"service_6_${role%:*}\""
		done

		echo "}"
		echo "}"
	} | ip netns exec tudp-svc nft -f -
}

# datagrams NAMESPACE ADDRESS PORT sends three datagrams from the
# namespace, each from a socket of its own.
datagrams() {
	count=0

	while [ "$count" -lt 3 ]; do
		echo tudp | ip netns exec "$1" socat -u - "UDP-SENDTO:$2:$3"
		count=$((count + 1))
	done
}

send() {
	for ns in tudp-veth tudp-tap; do
		for port in "$PORT_ALLOW" "$PORT_DENY" "$PORT_UNLISTED"; do
			datagrams "$ns" "$SERVICE4.2" "$port"
			datagrams "$ns" "[$SERVICE6:2]" "$port"
		done
	done

	datagrams tudp-uplink "$BRIDGE4.1" "$PORT_UPLINK"
	datagrams tudp-uplink "[$BRIDGE6:1]" "$PORT_UPLINK"
}

report() {
	nft list table inet tudp
	ip netns exec tudp-svc nft list table inet tudp
}

case "${1:-}" in
up | send | report | down) "$1" ;;
*)
	echo "usage: $0 up|send|report|down" >&2
	exit 2
	;;
esac
