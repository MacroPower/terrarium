package main

import "go.jacobcolvin.com/terrarium/internal/testspec"

// spec defines the test execution plan for a single e2e test case.
// The testrunner reads this from a JSON file passed via --spec.
type spec struct {
	ConfigPath      string      `json:"configPath"`
	InitCommand     string      `json:"initCommand"`
	ExtraCACertPath string      `json:"extraCACertPath,omitempty"`
	Assertions      []assertion `json:"assertions"`
	RootAssertions  []assertion `json:"rootAssertions"`
	LoopbackPort    int         `json:"loopbackPort,omitempty"`
	ValidateEnvoy   bool        `json:"validateEnvoy"`
	DaemonMode      bool        `json:"daemonMode,omitempty"`
	SkipDaemonCheck bool        `json:"skipDaemonCheck,omitempty"`
	Debug           bool        `json:"debug,omitempty"`
}

// assertion and result are aliases for the shared JSON shapes. The
// canonical definitions live in [testspec]; aliasing keeps internal
// call sites terse while guaranteeing the driver and testrunner
// cannot drift.
type (
	assertion = testspec.Assertion
	result    = testspec.Result
)
