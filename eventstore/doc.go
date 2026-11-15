// Package eventstore is an embedded SQLite event store for terrarium
// egress decisions. A [Store] records the [Event] values that the DNS
// proxy, the Envoy access-log gRPC server, and the firewall log reader
// emit. A [Reader] answers the queries of the `terrarium stats` CLI
// and of the `terrarium status` report.
//
// The data plane never blocks on the store. Producers call [Store.Emit],
// which performs a non-blocking send onto a buffered channel. A single
// writer goroutine drains the channel, batches inserts, and runs the
// retention pruner inline, so pruning never contends with writes for the
// SQLite write lock.
//
// Open a store with [Open]. Nil-valued [*Store] receivers are safe.
// [Store.Emit], [Store.RecordPolicy], and [Store.Close] are no-ops on
// a nil store, so callers take the same code path with stats
// disabled.
//
// A store also records the policy that its process enforces. The
// process calls [Store.RecordPolicy] after it applies a policy, at
// its start and after each reload. Each call adds one snapshot of the
// policy document, so [Reader.PolicyAt] returns the policy in force
// at the time of a given event. The unprivileged user of [WithUID]
// can read the database, so the caller removes each secret from the
// document before the call.
//
// Open a reader with [OpenReader], usually in another process than the
// one that writes. Each query of the store belongs in a [Reader]
// method, so that every consumer counts and filters events the same
// way. A [Reader] also reads a database that an earlier version of
// this package wrote. It returns an empty result for a table that the
// earlier schema does not hold.
package eventstore
