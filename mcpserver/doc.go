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
// # Bounds
//
// Each result has a bounded size. The list_instances, top_events,
// and list_events tools take a `limit`, which is [DefaultLimit] when
// the call omits it and [MaxLimit] at most. A string longer than
// [MaxFieldBytes] ends in [TruncationMarker] after that many bytes.
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
