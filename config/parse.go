package config

import (
	"bytes"
	"context"
	"fmt"

	"github.com/goccy/go-yaml"
	"go.jacobcolvin.com/niceyaml"

	_ "embed"
)

//go:embed defaults.yaml
var defaultsYAML []byte

// DefaultConfig returns a config decoded from the embedded defaults.yaml.
func DefaultConfig() *Config {
	cfg, err := parseConfigRaw(context.Background(), defaultsYAML)
	if err != nil {
		panic(fmt.Sprintf("parsing embedded defaults.yaml: %v", err))
	}

	return cfg
}

// MarshalConfig returns the given config as YAML bytes.
func MarshalConfig(cfg *Config) ([]byte, error) {
	var buf bytes.Buffer

	err := niceyaml.NewEncoder(&buf).Encode(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}

	return buf.Bytes(), nil
}

// MarshalDefaultConfig returns the default config as YAML bytes.
func MarshalDefaultConfig() ([]byte, error) {
	return MarshalConfig(DefaultConfig())
}

// parseConfigRaw parses a YAML terrarium config without validation.
func parseConfigRaw(ctx context.Context, data []byte) (*Config, error) {
	var cfg Config

	src := niceyaml.NewSourceFromBytes(data,
		niceyaml.WithDecodeOptions(yaml.DisallowUnknownField()),
	)
	dec, err := src.Decoder()
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	for _, doc := range dec.Documents() {
		err := doc.DecodeContext(ctx, &cfg)
		if err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}

	return &cfg, nil
}

// ParseConfig parses and validates a YAML terrarium config.
func ParseConfig(ctx context.Context, data []byte) (*Config, error) {
	cfg, err := parseConfigRaw(ctx, data)
	if err != nil {
		return nil, err
	}

	err = cfg.Validate()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
