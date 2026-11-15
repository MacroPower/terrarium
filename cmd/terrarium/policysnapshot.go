package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// recordPolicySnapshot records cfg in store as the policy that this
// process enforces from the time of the call. The init, daemon, and
// proxy modes call it after they apply the config at their start. The
// daemon calls it again after each reload that replaced the running
// config. A nil store is a no-op.
//
// The snapshot holds cfg as [config.MarshalConfig] writes it, which
// is the parsed and normalized config and not the bytes of the file
// at configPath. Every rule of `egress` and of `egressDeny` keeps its
// index, and [config.ParseConfig] reads the document back as the
// config that [config.Config.Redacted] returns for cfg.
//
// The sandboxed user can read the database of the store, and a header
// value of the policy can be a credential. The snapshot therefore
// holds [config.RedactedValue] in place of every header value that
// the policy sets, as [config.Config.Redacted] describes.
//
// For a config that does not marshal, recordPolicySnapshot logs a
// warning and records no snapshot. The process keeps running, because
// the data plane does not depend on the store.
func recordPolicySnapshot(ctx context.Context, store *eventstore.Store, cfg *config.Config, configPath string) {
	if store == nil {
		return
	}

	doc, err := config.MarshalConfig(cfg.Redacted())
	if err != nil {
		slog.WarnContext(ctx, "stats: policy snapshot not recorded", slog.Any("err", err))

		return
	}

	store.RecordPolicy(eventstore.PolicySnapshot{
		ConfigPath: absConfigPath(configPath),
		Mode:       securityMode(cfg),
		YAML:       string(doc),
	})
}

// securityMode returns the [eventstore.SecurityMode] of cfg.
func securityMode(cfg *config.Config) eventstore.SecurityMode {
	switch {
	case cfg.IsEgressUnrestricted():
		return eventstore.SecurityUnrestricted
	case cfg.IsEgressBlocked():
		return eventstore.SecurityBlocked
	default:
		return eventstore.SecurityFiltered
	}
}

// absConfigPath returns path as an absolute path. The event store
// then names the same config file whatever the working directory of
// the process that reads the store. It returns path unchanged when
// path is empty or when the working directory is not available.
func absConfigPath(path string) string {
	if path == "" {
		return ""
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}

	return abs
}
