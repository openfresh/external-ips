// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package inbound

import (
	"fmt"
)

type ProviderIDs []string

type InboundRules struct {
	Name        string
	Rules       []InboundRule
	ProviderIDs ProviderIDs
}

func (ir InboundRules) String() string {
	result := ir.Name
	for _, r := range ir.Rules {
		result += fmt.Sprintf(" %s:%d", r.Protocol, r.Port)
	}
	return result
}

func (ir *InboundRules) Same(o *InboundRules) bool {
	if len(ir.Rules) != len(o.Rules) {
		return false
	}

	for i, r := range ir.Rules {
		if r.Protocol != o.Rules[i].Protocol {
			return false
		}
		if r.Port != o.Rules[i].Port {
			return false
		}
	}
	return true
}

type InboundRule struct {
	Protocol string
	Port     int
}

func NewInboundRules() *InboundRules {
	rules := make([]InboundRule, 0)
	providerIDs := make([]string, 0)

	return &InboundRules{
		Rules:       rules,
		ProviderIDs: providerIDs,
	}
}
