// Package mcpserver serves the terrarium event store to a Model
// Context Protocol (MCP) client, such as a coding agent, as a set of
// tools. The `terrarium mcp` command runs a [Server] on its standard
// input and output.
//
// # Reads
//
// No tool writes. Each tool call opens the database with
// [eventstore.OpenReader], which opens the file for reads only, and
// closes it when the call returns. The reads leave the database file
// and its `-wal` file as they found them. No tool takes SQL or a file path,
// and each tool declares the read-only hint of the protocol.
//
// A [Server] asks its [LocateFunc] for the path of the database at
// each tool call. The server can therefore start before the process
// that creates the database. A tool call on a missing database
// returns a tool error that wraps [ErrNoDatabase] and names the path.
// The server keeps running, and a later call reads the database
// after it appears.
//
// # Windows and instances
//
// The event tools read the events of one time window and of one
// instance, which is one run of terrarium. The window bounds accept
// the values of [eventstore.ParseSince] and [eventstore.ParseUntil].
// A call that names no instance reads the instance of
// [eventstore.Reader.LatestInstanceID], as the `terrarium stats`
// commands do. Each result names the instance that it read.
//
// # Policy snapshots
//
// The policy tools read the snapshots that an instance records each
// time that it applies a policy. The get_policy tool returns one
// snapshot, which is the latest one of the instance or the one of
// [eventstore.Reader.PolicyAt] for a time. The time of an event
// selects the policy that decided the event, except during a reload.
// The result holds the stored policy document and its `egress` and
// `egressDeny` rules, each rule with its index in its list. The rule
// index and the reason of a firewall event name a rule by that index.
//
// A reload switches the firewall rules and the DNS proxy before the
// instance records the snapshot of the reload. An event from that time
// can therefore come from the policy of the next snapshot. For the
// time of such an event, get_policy returns the snapshot before it.
//
// The list_policies tool returns the snapshots of an instance without
// their documents, so a client can see each reload and whether it
// changed the stored document. A reload that changes only a header
// value leaves the stored document unchanged, because the document
// holds the redaction marker in place of each header value.
//
// The store holds
// [go.jacobcolvin.com/terrarium/config.RedactedValue] in place of
// each header value of a policy, because such a value can be a
// credential. The policy tools read only the store, so they return
// that marker and never the value.
//
// A database from before the policy snapshots holds none, and
// neither does an instance that recorded none. The policy tools then
// return a result without a snapshot and with a message that says
// so, not a tool error.
//
// # Bounds
//
// Each result has a bounded size. The list_instances, top_events,
// list_events, and list_policies tools take a `limit`, which is
// [DefaultLimit] when the call omits it and [MaxLimit] at most.
// Strings longer than [MaxFieldBytes] end in [TruncationMarker] after
// that many bytes, except in the policy document and the rules of the
// get_policy tool.
//
// [MaxPolicyBytes] bounds the policy document of the get_policy tool
// and each rule of its two rule lists. A string inside a rule can
// therefore hold up to that many bytes. A rule whose JSON form is
// longer than the bound is a truncated string, and it is the only
// rule of its list. Every other rule list ends before the rule that
// takes the JSON forms of its rules past the bound. The result still
// holds the number of rules in the policy. The `first_rule`
// argument selects the first rule of both lists, so a client reads
// the remaining rules with another call.
//
// # Untrusted values
//
// The sandboxed workload chooses the domain names, the TLS server
// names, and the HTTP methods and paths of its own requests. It can
// write text there that reads like an instruction to the client. The
// tools return those values only as JSON field values, and the
// instructions of the server tell the client to treat them as
// untrusted data.
package mcpserver
