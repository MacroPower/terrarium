// Package logprefix encodes and decodes the `log prefix` payload
// terrarium attaches to nftables [Log] expressions.
//
// The encoding is a small string the rule emitter writes and the
// nflog reader parses. Keeping both producer and consumer in one
// package means a wire-format change has to land in one place.
//
// The on-wire form is `TERRARIUM_<KIND>:` optionally followed by
// `rule=<idx>`, with a single trailing space so syslog readers see
// space-delimited tokens. The kinds are [KindAllow], [KindDeny],
// and [KindLeak]. [Decode] accepts the exact combinations [Encode]
// produces and rejects anything else.
//
// Output stays well under the 64-byte nftables `log prefix` cap.
// See [Encode] for the exact bound.
//
// [Log]: https://pkg.go.dev/github.com/google/nftables/expr#Log
package logprefix
