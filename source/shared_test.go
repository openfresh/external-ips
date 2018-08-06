// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package source

import (
	"github.com/openfresh/external-ips/firewall/inbound"
	"testing"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/setting"
)

// test helper functions
func validateIPs(t *testing.T, ips, expected endpoint.Targets) {
	if !ips.Same(expected) {
		t.Errorf("expected %s, got %s", expected, ips)
	}
}

func validateSetting(t *testing.T, setting, expected *setting.ExternalIPSetting) {
	validateEndpoints(t, setting.Endpoints, expected.Endpoints)
	validateInboundRules(t, setting.InboundRules, expected.InboundRules)
}

func validateEndpoints(t *testing.T, endpoints, expected []*endpoint.Endpoint) {
	if len(endpoints) != len(expected) {
		t.Fatalf("expected %d endpoints, got %d", len(expected), len(endpoints))
	}

	for i := range endpoints {
		validateEndpoint(t, endpoints[i], expected[i])
	}
}

func validateEndpoint(t *testing.T, endpoint, expected *endpoint.Endpoint) {
	if endpoint.DNSName != expected.DNSName {
		t.Errorf("expected %s, got %s", expected.DNSName, endpoint.DNSName)
	}

	if !endpoint.Targets.Same(expected.Targets) {
		t.Errorf("expected %s, got %s", expected.Targets, endpoint.Targets)
	}

	if endpoint.RecordTTL != expected.RecordTTL {
		t.Errorf("expected %v, got %v", expected.RecordTTL, endpoint.RecordTTL)
	}

	// if non-empty record type is expected, check that it matches.
	if expected.RecordType != "" && endpoint.RecordType != expected.RecordType {
		t.Errorf("expected %s, got %s", expected.RecordType, endpoint.RecordType)
	}
}

func validateInboundRules(t *testing.T, rules, expected []*inbound.InboundRules) {
	if len(rules) != len(expected) {
		t.Fatalf("expected %d rules, got %d", len(expected), len(rules))
	}

	for i := range rules {
		validateInbouldRule(t, rules[i], expected[i])
	}
}

func validateInbouldRule(t *testing.T, rule, expected *inbound.InboundRules) {
	if rule.Name != expected.Name {
		t.Errorf("expected %s, got %s", expected.Name, rule.Name)
	}

	if !rule.Same(expected) {
		t.Errorf("expected %s, got %s", expected.String(), rule.String())
	}

	if !rule.ProviderIDs.Same(expected.ProviderIDs) {
		t.Errorf("expected %s, got %s", expected.ProviderIDs, rule.ProviderIDs)
	}
}
