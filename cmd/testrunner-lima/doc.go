// Command testrunner-lima orchestrates e2e tests inside a Lima VM
// running the terrarium daemon. It builds a testrunner binary for
// linux, copies it into the VM, and for each test case: writes a
// terrarium config, sets up target services (nginx, socat), restarts
// the daemon, writes a test spec, and runs the testrunner in daemon
// mode inside the VM.
//
// Tests run sequentially against a single shared VM. The testrunner
// binary reuses the same assertion framework as the container e2e
// tests but skips terrarium init (the daemon is already active).
//
// Usage:
//
//	testrunner-lima --vm-name=terrarium             # run all tests
//	testrunner-lima --vm-name=terrarium --test=X    # run single test
//	testrunner-lima --vm-name=terrarium --list       # list tests
package main
