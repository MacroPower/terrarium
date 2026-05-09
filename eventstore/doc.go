// Package eventstore is an embedded SQLite event store for terrarium
// egress decisions. It records [Event] values written by the DNS proxy
// and the Envoy access-log gRPC server, exposing the resulting database
// to the `terrarium stats` CLI.
//
// The data plane never blocks on the store. Producers call [Store.Emit],
// which performs a non-blocking send onto a buffered channel. A single
// writer goroutine drains the channel, batches inserts, and runs the
// retention pruner inline, so pruning never contends with writes for the
// SQLite write lock.
//
// Open a store with [Open]. Nil-valued [*Store] receivers are safe;
// [Store.Emit] and [Store.Close] are no-ops on a nil store so callers
// can take the same code path with stats disabled.
package eventstore
