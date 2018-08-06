// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package inbound

import (
	"fmt"
	"sort"
)

type ProviderIDs []string

func (t ProviderIDs) Len() int {
	return len(t)
}

func (t ProviderIDs) Less(i, j int) bool {
	return t[i] < t[j]
}

func (t ProviderIDs) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

// Same compares to Targets and returns true if they are completely identical
func (t ProviderIDs) Same(o ProviderIDs) bool {
	if len(t) != len(o) {
		return false
	}
	sort.Stable(t)
	sort.Stable(o)

	for i, e := range t {
		if e != o[i] {
			return false
		}
	}
	return true
}

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
