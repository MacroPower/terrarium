package config_test

import "go.jacobcolvin.com/terrarium/config"

func egressRules(rules ...config.EgressRule) *[]config.EgressRule {
	return &rules
}
