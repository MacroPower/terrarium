package jail

// Config is a test-only alias for [config].
type Config = config

var (
	// InternalExec is a test-only alias for [exec] that accepts an
	// injected [Config].
	InternalExec = exec

	// CurrentProfile is a test-only alias for [currentProfile].
	CurrentProfile = currentProfile

	// ProfileLoaded is a test-only alias for [profileLoaded].
	ProfileLoaded = profileLoaded
)

// NewConfig builds a [Config] with the given procRoot and
// apparmorRoot. Write and execve are defaulted to stubs the caller
// can override via [Config.SetWrite] and [Config.SetExecve].
func NewConfig(procRoot, apparmorRoot string) *Config {
	return &config{
		procRoot:     procRoot,
		apparmorRoot: apparmorRoot,
	}
}

// SetWrite overrides the exec-attr write function on a test [Config].
func (c *config) SetWrite(fn func(fd int, p []byte) (int, error)) {
	c.write = fn
}

// SetExecve overrides the execve function on a test [Config].
func (c *config) SetExecve(fn func(path string, argv, envv []string) error) {
	c.execve = fn
}
