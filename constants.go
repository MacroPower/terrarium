package terrarium

const (
	// UID is the numeric user ID for the sandboxed non-root user.
	UID = "1000"

	// GID is the numeric group ID for the sandboxed non-root user.
	GID = "1000"

	// EnvoyUID is the numeric user/group ID for the Envoy proxy process.
	EnvoyUID = "999"

	// Username is the non-root user created inside the dev container.
	Username = "dev"

	// HomeDir is the home directory for the dev container user.
	HomeDir = "/home/dev"

	// HMBin is the stable path to home-manager managed binaries.
	HMBin = HomeDir + "/.local/state/home-manager/gcroots/current-home/home-path/bin"

	// ConfigPath is the path to terrarium YAML config file.
	ConfigPath = "/etc/terrarium/config.yaml"
)

const (
	protoTCP  = "tcp"
	protoUDP  = "udp"
	protoSCTP = "sctp"
)
