// Package accesslog implements an Envoy AccessLog Service (gRPC ALS)
// server bound to a Unix domain socket. Envoy connects to the socket,
// opens a long-lived stream, and pushes HTTPAccessLogEntry and
// TCPAccessLogEntry messages. Each entry translates to one
// [eventstore.Event] that the writer goroutine persists into SQLite.
//
// The server uses the standard envoy.service.accesslog.v3 contract.
// It runs in the same process as terrarium init or daemon (no
// sidecar). Lifetime is owned by [Start] and [Server.Shutdown].
package accesslog
