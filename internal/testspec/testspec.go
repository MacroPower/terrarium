// Package testspec holds the JSON shapes shared between the VM-side
// testrunner and the host-side testrunner-lima driver. Both binaries
// marshal these types over a JSON spec file, so they must agree on
// field names and tags.
package testspec

// Assertion defines a single test assertion. [Assertion.Type] selects
// the assertion implementation on the testrunner side; remaining
// fields are type-specific parameters. Unused fields are omitted from
// the JSON via omitempty tags.
type Assertion struct {
	Type     string   `json:"type"`
	URL      string   `json:"url,omitempty"`
	Method   string   `json:"method,omitempty"`
	Header   string   `json:"header,omitempty"`
	Body     string   `json:"body,omitempty"`
	Host     string   `json:"host,omitempty"`
	Addr     string   `json:"addr,omitempty"`
	Expected string   `json:"expected,omitempty"`
	File     string   `json:"file,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	UID      string   `json:"uid,omitempty"`
	Desc     string   `json:"desc"`
	Cmd      string   `json:"cmd,omitempty"`
	Op       string   `json:"op,omitempty"`
	Args     []string `json:"args,omitempty"`
	Port     int      `json:"port,omitempty"`
}

// Result captures the outcome of a single [Assertion] execution.
type Result struct {
	Status string `json:"status"`
	Desc   string `json:"desc"`
	Detail string `json:"detail"`
}
