package config_test

import (
	"strconv"

	"go.jacobcolvin.com/terrarium/config"
)

func egressRules(rules ...config.EgressRule) *[]config.EgressRule {
	return &rules
}

func egressDenyRules(rules ...config.EgressDenyRule) *[]config.EgressDenyRule {
	return &rules
}

// addHeaderMatches returns n header matches with the ADD mismatch
// action. Each header match names its own header.
func addHeaderMatches(n int) []config.HeaderMatch {
	matches := make([]config.HeaderMatch, 0, n)

	for i := range n {
		matches = append(matches, config.HeaderMatch{
			Name:     "X-Add-" + strconv.Itoa(i),
			Value:    "value",
			Mismatch: config.MismatchADD,
		})
	}

	return matches
}
