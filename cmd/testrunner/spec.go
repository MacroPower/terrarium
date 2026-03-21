package main

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
}

// assertion defines a single test assertion to execute inside the
// terrarium container. The [assertion.Type] field selects the assertion
// implementation; remaining fields are type-specific parameters.
type assertion struct {
	Type     string `json:"type"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`
	Header   string `json:"header,omitempty"`
	Body     string `json:"body,omitempty"`
	Host     string `json:"host,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Expected string `json:"expected,omitempty"`
	File     string `json:"file,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Domain   string `json:"domain,omitempty"`
	UID      string `json:"uid,omitempty"`
	Desc     string `json:"desc"`
	Port     int    `json:"port,omitempty"`
}

// result captures the outcome of a single assertion execution.
type result struct {
	Status string `json:"status"`
	Desc   string `json:"desc"`
	Detail string `json:"detail"`
}
