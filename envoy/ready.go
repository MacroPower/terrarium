package envoy

// readyListenerName is the name of the listener that [BuildReadyOverlay]
// adds, and the stat prefix of its HTTP connection manager.
const readyListenerName = "ready"

// The mode of the ready socket. The mode gives every user write access,
// which a connection requires, so the directory of the socket decides
// which users can connect. See [BuildReadyOverlay].
const readySocketMode = 0o666

// ReadyOverlay is a partial bootstrap that adds the ready listener to
// the bootstrap that Envoy loads from a file. A caller passes the YAML
// form of the overlay to Envoy in the --config-yaml flag. Envoy then
// appends the listener of the overlay to the listeners of the file.
//
// The ready listener binds a Unix domain socket and answers every HTTP
// request with status 200. A worker thread of Envoy sends the answer.
// Envoy starts its worker threads after it calls listen on every
// listener of the bootstrap, and it exits when it cannot bind one of
// them. An answer therefore shows that the listeners of the Envoy
// process that holds the socket accept connections.
//
// Envoy keeps running without a listener whose listen call does not
// succeed after a bind that did succeed, and the ready listener still
// answers. Envoy binds a listener when it loads the bootstrap, and it
// calls listen when it starts its workers, after its clusters
// initialize. A STRICT_DNS cluster initializes after its first DNS
// lookup, so the interval between the bind and the listen call
// includes that lookup. The listen call does not succeed when another
// process binds the same address with SO_REUSEADDR and listens there
// in that interval. That process can bind before or after the bind of
// Envoy.
//
// The overlay does not change the bootstrap file, so it also works for
// a bootstrap that an earlier run or an earlier release generated.
//
// Create instances with [BuildReadyOverlay].
type ReadyOverlay struct {
	StaticResources readyResources `yaml:"static_resources"`
}

// readyResources holds the listeners of a [ReadyOverlay]. It leaves
// out the clusters, because Envoy merges every field that the overlay
// names into the bootstrap of the file.
type readyResources struct {
	Listeners []Listener `yaml:"listeners"`
}

// BuildReadyOverlay creates a new [ReadyOverlay] whose ready listener
// binds the Unix domain socket at socketPath.
//
// Envoy removes a file at socketPath before it binds the socket, and
// it gives the socket the mode 0o666. The caller must therefore limit
// access to the directory of socketPath, which must exist. The user
// that runs Envoy must have write access to the directory.
func BuildReadyOverlay(socketPath string) ReadyOverlay {
	return ReadyOverlay{
		StaticResources: readyResources{
			Listeners: []Listener{{
				Name: readyListenerName,
				Address: &address{Pipe: &pipeAddress{
					Path: socketPath,
					Mode: readySocketMode,
				}},
				FilterChains: []filterChain{{
					Filters: []filter{{
						Name: hcmFilterName,
						TypedConfig: httpConnManagerConfig{
							AtType:     hcmTypeURL,
							StatPrefix: readyListenerName,
							RouteConfig: routeConfig{
								VirtualHosts: []virtualHost{{
									Name:    readyListenerName,
									Domains: []string{"*"},
									Routes: []route{{
										Match:          routeMatch{Prefix: "/"},
										DirectResponse: &directResponseAction{Status: 200},
									}},
								}},
							},
							HTTPFilters: []filter{{
								Name: httpRouterFilterName,
								TypedConfig: typeOnly{
									AtType: httpRouterTypeURL,
								},
							}},
						},
					}},
				}},
			}},
		},
	}
}
