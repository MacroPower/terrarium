package status

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/goccy/go-yaml"

	"go.jacobcolvin.com/terrarium/envoy"
)

// collectEnvoy reads the generated Envoy bootstrap YAML at path and
// extracts the listener ports. A missing file is not an error: it
// simply means `terrarium generate` has not run yet, so the section
// reports [EnvoySection.NotGenerated] and no listeners.
func collectEnvoy(path string) EnvoySection {
	s := EnvoySection{ConfigPath: path}

	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.NotGenerated = true
			return s
		}

		s.Err = err

		return s
	}

	var bs envoy.Bootstrap

	err = yaml.Unmarshal(data, &bs)
	if err != nil {
		s.Err = fmt.Errorf("parsing envoy config: %w", err)
		return s
	}

	s.Listeners = listenerPorts(bs)

	return s
}

// listenerPorts extracts a deduplicated, ascending list of listener
// ports from a parsed bootstrap. Each listener can bind to both IPv4
// and IPv6 via AdditionalAddresses on the same port; ports are
// deduped rather than addresses because the rendered output is a
// port list only.
func listenerPorts(bs envoy.Bootstrap) []int {
	seen := make(map[int]bool)

	for _, l := range bs.StaticResources.Listeners {
		port := l.Address.SocketAddress.PortValue
		if port > 0 {
			seen[port] = true
		}

		for _, add := range l.AdditionalAddresses {
			port := add.Address.SocketAddress.PortValue
			if port > 0 {
				seen[port] = true
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}

	sort.Ints(ports)

	return ports
}
