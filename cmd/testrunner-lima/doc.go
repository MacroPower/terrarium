// Package main provides e2e tests for the terrarium daemon running
// inside a Lima VM. Tests build a testrunner binary for linux, copy it
// into the VM, and for each test case: write a terrarium config, set
// up target services (nginx, socat), restart the daemon, write a test
// spec, and run the testrunner in daemon mode inside the VM.
//
// Tests run sequentially against a single shared VM. The testrunner
// binary reuses the same assertion framework as the container e2e
// tests but skips terrarium init (the daemon is already active).
//
// Usage:
//
//	go test -v -count=1 -timeout=30m ./cmd/testrunner-lima
//	go test -v -count=1 -timeout=30m -run TestVM/vm-deny-all ./cmd/testrunner-lima
//	LIMA_VM=myvm go test -v -count=1 -timeout=30m ./cmd/testrunner-lima
package main
