package eventstore

import (
	"fmt"
	"time"
)

// ParseSince parses the start of a time window for [Filter.Since]. The
// value is a Go duration, such as 30m or 24h, or an RFC 3339 time. A
// duration names the time that long before now. The empty value
// returns the zero time, which sets no start.
//
// The `terrarium stats` flags and the tools of `terrarium mcp` both
// parse their windows here, so both accept the same values.
func ParseSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	d, err := time.ParseDuration(value)
	if err == nil {
		return now.Add(-d), nil
	}

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a duration or an RFC 3339 time: %w", value, err)
	}

	return t, nil
}

// ParseUntil parses the end of a time window for [Filter.Until]. The
// value is an RFC 3339 time. The empty value returns now.
func ParseUntil(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return now, nil
	}

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not an RFC 3339 time: %w", value, err)
	}

	return t, nil
}
