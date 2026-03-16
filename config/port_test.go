package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestResolvePort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  uint16
		err   bool
	}{
		"numeric":            {input: "443", want: 443},
		"numeric zero":       {input: "0", want: 0},
		"named https":        {input: "https", want: 443},
		"named http":         {input: "http", want: 80},
		"named dns":          {input: "dns", want: 53},
		"named domain":       {input: "domain", want: 53},
		"named dns-tcp":      {input: "dns-tcp", want: 53},
		"named ftp":          {input: "ftp", want: 21},
		"named ssh":          {input: "ssh", want: 22},
		"named smtp":         {input: "smtp", want: 25},
		"named ntp":          {input: "ntp", want: 123},
		"named ldap":         {input: "ldap", want: 389},
		"named ldaps":        {input: "ldaps", want: 636},
		"named mysql":        {input: "mysql", want: 3306},
		"named postgresql":   {input: "postgresql", want: 5432},
		"named redis":        {input: "redis", want: 6379},
		"named syslog":       {input: "syslog", want: 514},
		"case insensitive":   {input: "HTTP", want: 80},
		"mixed case":         {input: "Https", want: 443},
		"unknown name":       {input: "kafka", err: true},
		"invalid syntax":     {input: "abc!!", err: true},
		"leading hyphen":     {input: "-http", err: true},
		"trailing hyphen":    {input: "http-", err: true},
		"consecutive hyphen": {input: "dns--tcp", err: true},
		"empty":              {input: "", err: true},
		"digits only":        {input: "123", want: 123},
		"port 65535":         {input: "65535", want: 65535},
		"port 65536":         {input: "65536", err: true},
		"port 70000":         {input: "70000", err: true},
		"large port":         {input: "100000", err: true},
		"negative":           {input: "-1", err: true},
		"negative zero":      {input: "-0", err: true},
		"hex rejected":       {input: "0x1BB", err: true},
		"octal rejected":     {input: "0o777", err: true},
		"max int rejected":   {input: "2147483647", err: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := config.ResolvePort(tt.input)
			if tt.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNamedPortResolution(t *testing.T) {
	t.Parallel()

	t.Run("ResolvePorts with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "https"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{443}, cfg.ResolvePorts())
	})

	t.Run("ResolveOpenPorts with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "http"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{80}, cfg.ResolveOpenPorts())
	})

	t.Run("ResolveRulesForPort with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "https"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())

		rules := cfg.ResolveRulesForPort(443)
		require.Len(t, rules, 1)
		assert.Equal(t, "example.com", rules[0].Domain)
	})

	t.Run("case insensitivity in resolution", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "HTTPS"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{443}, cfg.ResolvePorts())
	})
}
