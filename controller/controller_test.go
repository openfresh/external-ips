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

package controller

import (
	"errors"
	"github.com/openfresh/external-ips/extip/extip"
	"github.com/openfresh/external-ips/firewall/inbound"
	"sort"
	"testing"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/dns/plan"
	"github.com/openfresh/external-ips/dns/provider"
	"github.com/openfresh/external-ips/dns/registry"
	eipplan "github.com/openfresh/external-ips/extip/plan"
	eipprovider "github.com/openfresh/external-ips/extip/provider"
	eipregistry "github.com/openfresh/external-ips/extip/registry"
	fwplan "github.com/openfresh/external-ips/firewall/plan"
	fwprovider "github.com/openfresh/external-ips/firewall/provider"
	fwregistry "github.com/openfresh/external-ips/firewall/registry"
	"github.com/openfresh/external-ips/internal/testutils"
	"github.com/openfresh/external-ips/setting"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider returns mock endpoints and validates changes.
type mockProvider struct {
	RecordsStore  []*endpoint.Endpoint
	ExpectChanges *plan.Changes
}

// Records returns the desired mock endpoints.
func (p *mockProvider) Records() ([]*endpoint.Endpoint, error) {
	return p.RecordsStore, nil
}

// ApplyChanges validates that the passed in changes satisfy the assumtions.
func (p *mockProvider) ApplyChanges(changes *plan.Changes) error {
	if len(changes.Create) != len(p.ExpectChanges.Create) {
		return errors.New("number of created records is wrong")
	}

	for i := range changes.Create {
		if changes.Create[i].DNSName != p.ExpectChanges.Create[i].DNSName || !changes.Create[i].Targets.Same(p.ExpectChanges.Create[i].Targets) {
			return errors.New("created record is wrong")
		}
	}

	for i := range changes.UpdateNew {
		if changes.UpdateNew[i].DNSName != p.ExpectChanges.UpdateNew[i].DNSName || !changes.UpdateNew[i].Targets.Same(p.ExpectChanges.UpdateNew[i].Targets) {
			return errors.New("delete record is wrong")
		}
	}

	for i := range changes.UpdateOld {
		if changes.UpdateOld[i].DNSName != p.ExpectChanges.UpdateOld[i].DNSName || !changes.UpdateOld[i].Targets.Same(p.ExpectChanges.UpdateOld[i].Targets) {
			return errors.New("delete record is wrong")
		}
	}

	for i := range changes.Delete {
		if changes.Delete[i].DNSName != p.ExpectChanges.Delete[i].DNSName || !changes.Delete[i].Targets.Same(p.ExpectChanges.Delete[i].Targets) {
			return errors.New("delete record is wrong")
		}
	}

	return nil
}

// newMockProvider creates a new mockProvider returning the given endpoints and validating the desired changes.
func newMockProvider(endpoints []*endpoint.Endpoint, changes *plan.Changes) provider.Provider {
	dnsProvider := &mockProvider{
		RecordsStore:  endpoints,
		ExpectChanges: changes,
	}

	return dnsProvider
}

// mockProvider returns mock endpoints and validates changes.
type mockFWProvider struct {
	RulesStore    []*inbound.InboundRules
	ExpectChanges *fwplan.Changes
}

// Records returns the desired mock endpoints.
func (p *mockFWProvider) Rules() ([]*inbound.InboundRules, error) {
	return p.RulesStore, nil
}

// ApplyChanges validates that the passed in changes satisfy the assumtions.
func (p *mockFWProvider) ApplyChanges(changes *fwplan.Changes) error {
	if len(changes.Create) != len(p.ExpectChanges.Create) {
		return errors.New("number of created rule is wrong")
	}

	for i := range changes.Create {
		if changes.Create[i].Name != p.ExpectChanges.Create[i].Name ||
			!changes.Create[i].Same(p.ExpectChanges.Create[i]) ||
			!changes.Create[i].ProviderIDs.Same(p.ExpectChanges.Create[i].ProviderIDs) {
			return errors.New("created rule is wrong")
		}
	}

	for i := range changes.UpdateNew {
		if changes.UpdateNew[i].Name != p.ExpectChanges.UpdateNew[i].Name ||
			!changes.UpdateNew[i].Same(p.ExpectChanges.UpdateNew[i]) ||
			!changes.UpdateNew[i].ProviderIDs.Same(p.ExpectChanges.UpdateNew[i].ProviderIDs) {
			return errors.New("update new rule is wrong")
		}
	}

	for i := range changes.UpdateOld {
		if changes.UpdateOld[i].Name != p.ExpectChanges.UpdateOld[i].Name ||
			!changes.UpdateOld[i].Same(p.ExpectChanges.UpdateOld[i]) ||
			!changes.UpdateOld[i].ProviderIDs.Same(p.ExpectChanges.UpdateOld[i].ProviderIDs) {
			return errors.New("update old rule is wrong")
		}
	}

	for i := range changes.Delete {
		if changes.Delete[i].Name != p.ExpectChanges.Delete[i].Name ||
			!changes.Delete[i].Same(p.ExpectChanges.Delete[i]) ||
			!changes.Delete[i].ProviderIDs.Same(p.ExpectChanges.Delete[i].ProviderIDs) {
			return errors.New("delete rule is wrong")
		}
	}

	sort.Sort(fwplan.ByProviderID(changes.Set))
	sort.Sort(fwplan.ByProviderID(p.ExpectChanges.Set))
	for i := range changes.Set {
		if changes.Set[i].ProviderID != p.ExpectChanges.Set[i].ProviderID ||
			changes.Set[i].RulesName != p.ExpectChanges.Set[i].RulesName {
			return errors.New("set rule is wrong")
		}
	}

	sort.Sort(fwplan.ByProviderID(changes.Unset))
	sort.Sort(fwplan.ByProviderID(p.ExpectChanges.Unset))
	for i := range changes.Unset {
		if changes.Unset[i].ProviderID != p.ExpectChanges.Unset[i].ProviderID ||
			changes.Unset[i].RulesName != p.ExpectChanges.Unset[i].RulesName {
			return errors.New("unset rule is wrong")
		}
	}

	return nil
}

// newMockProvider creates a new mockProvider returning the given endpoints and validating the desired changes.
func newMockFWProvider(rules []*inbound.InboundRules, changes *fwplan.Changes) fwprovider.Provider {
	fwProvider := &mockFWProvider{
		RulesStore:    rules,
		ExpectChanges: changes,
	}

	return fwProvider
}

// mockProvider returns mock endpoints and validates changes.
type mockEipProvider struct {
	ExtIPsStore   []*extip.ExtIP
	ExpectChanges *eipplan.Changes
}

// Records returns the desired mock endpoints.
func (p *mockEipProvider) ExtIPs() ([]*extip.ExtIP, error) {
	return p.ExtIPsStore, nil
}

// ApplyChanges validates that the passed in changes satisfy the assumtions.
func (p *mockEipProvider) ApplyChanges(changes *eipplan.Changes) error {
	sort.Sort(extip.BySvcName(changes.UpdateNew))
	sort.Sort(extip.BySvcName(p.ExpectChanges.UpdateNew))
	for i := range changes.UpdateNew {
		if changes.UpdateNew[i].SvcName != p.ExpectChanges.UpdateNew[i].SvcName ||
			!changes.UpdateNew[i].ExtIPs.Same(p.ExpectChanges.UpdateNew[i].ExtIPs) {
			return errors.New("update new eips is wrong")
		}
	}

	sort.Sort(extip.BySvcName(changes.UpdateOld))
	sort.Sort(extip.BySvcName(p.ExpectChanges.UpdateOld))
	for i := range changes.UpdateOld {
		if changes.UpdateOld[i].SvcName != p.ExpectChanges.UpdateOld[i].SvcName ||
			!changes.UpdateOld[i].ExtIPs.Same(p.ExpectChanges.UpdateOld[i].ExtIPs) {
			return errors.New("update old eips is wrong")
		}
	}

	return nil
}

// newMockProvider creates a new mockProvider returning the given endpoints and validating the desired changes.
func newMockEipProvider(extips []*extip.ExtIP, changes *eipplan.Changes) eipprovider.Provider {
	eipProvider := &mockEipProvider{
		ExtIPsStore:   extips,
		ExpectChanges: changes,
	}

	return eipProvider
}

// TestRunOnce tests that RunOnce correctly orchestrates the different components.
func TestRunOnce(t *testing.T) {
	// Fake some desired endpoints coming from our source.
	source := new(testutils.MockSource)
	source.On("ExternalIPSetting").Return(&setting.ExternalIPSetting{
		Endpoints: []*endpoint.Endpoint{
			{
				DNSName: "create-record",
				Targets: endpoint.Targets{"1.2.3.4"},
			},
			{
				DNSName: "update-record",
				Targets: endpoint.Targets{"8.8.4.4"},
			},
		},
		InboundRules: []*inbound.InboundRules{
			{
				Name: "create-rule",
				Rules: []inbound.InboundRule{
					{Protocol: "udp", Port: 9900},
				},
				ProviderIDs: inbound.ProviderIDs{"bbc", "zyx"},
			},
			{
				Name: "update-rule",
				Rules: []inbound.InboundRule{
					{Protocol: "udp", Port: 9800},
				},
				ProviderIDs: inbound.ProviderIDs{"abc", "zyx"},
			},
		},
		ExtIPs: []*extip.ExtIP{
			{
				SvcName: "update-svc",
				ExtIPs:  endpoint.Targets{"3.2.5.4"},
			},
		},
	}, nil)

	// Fake some existing records in our DNS provider and validate some desired changes.
	provider := newMockProvider(
		[]*endpoint.Endpoint{
			{
				DNSName: "update-record",
				Targets: endpoint.Targets{"8.8.8.8"},
			},
			{
				DNSName: "delete-record",
				Targets: endpoint.Targets{"4.3.2.1"},
			},
		},
		&plan.Changes{
			Create: []*endpoint.Endpoint{
				{DNSName: "create-record", Targets: endpoint.Targets{"1.2.3.4"}},
			},
			UpdateNew: []*endpoint.Endpoint{
				{DNSName: "update-record", Targets: endpoint.Targets{"8.8.4.4"}},
			},
			UpdateOld: []*endpoint.Endpoint{
				{DNSName: "update-record", Targets: endpoint.Targets{"8.8.8.8"}},
			},
			Delete: []*endpoint.Endpoint{
				{DNSName: "delete-record", Targets: endpoint.Targets{"4.3.2.1"}},
			},
		},
	)

	fwprovider := newMockFWProvider(
		[]*inbound.InboundRules{
			{
				Name: "update-rule",
				Rules: []inbound.InboundRule{
					{Protocol: "udp", Port: 5000},
				},
				ProviderIDs: inbound.ProviderIDs{"abc", "zyx"},
			},
			{
				Name: "delete-rule",
				Rules: []inbound.InboundRule{
					{Protocol: "tcp", Port: 80},
				},
				ProviderIDs: inbound.ProviderIDs{"def", "opq"},
			},
		},
		&fwplan.Changes{
			Create: []*inbound.InboundRules{
				{
					Name: "create-rule",
					Rules: []inbound.InboundRule{
						{Protocol: "udp", Port: 9900},
					},
					ProviderIDs: inbound.ProviderIDs{"bbc", "zyx"},
				},
			},
			UpdateNew: []*inbound.InboundRules{
				{
					Name: "update-rule",
					Rules: []inbound.InboundRule{
						{Protocol: "udp", Port: 9800},
					},
					ProviderIDs: inbound.ProviderIDs{"abc", "zyx"},
				},
			},
			UpdateOld: []*inbound.InboundRules{
				{
					Name: "update-rule",
					Rules: []inbound.InboundRule{
						{Protocol: "udp", Port: 5000},
					},
					ProviderIDs: inbound.ProviderIDs{"abc", "zyx"},
				},
			},
			Delete: []*inbound.InboundRules{
				{
					Name: "delete-rule",
					Rules: []inbound.InboundRule{
						{Protocol: "tcp", Port: 80},
					},
					ProviderIDs: inbound.ProviderIDs{"def", "opq"},
				},
			},
			Set: []*fwplan.InstanceRule{
				{ProviderID: "bbc", RulesName: "create-rule"},
				{ProviderID: "zyx", RulesName: "create-rule"},
			},
			Unset: []*fwplan.InstanceRule{
				{ProviderID: "def", RulesName: "delete-rule"},
				{ProviderID: "opq", RulesName: "delete-rule"},
			},
		},
	)

	eipprovider := newMockEipProvider(
		[]*extip.ExtIP{
			{
				SvcName: "update-svc",
				ExtIPs:  endpoint.Targets{"8.8.8.8"},
			},
			{
				SvcName: "delete-svc",
				ExtIPs:  endpoint.Targets{"4.3.2.1"},
			},
		},
		&eipplan.Changes{
			UpdateNew: []*extip.ExtIP{
				{SvcName: "update-svc", ExtIPs: endpoint.Targets{"3.2.5.4"}},
				{SvcName: "delete-svc", ExtIPs: endpoint.Targets{}},
			},
			UpdateOld: []*extip.ExtIP{
				{SvcName: "update-svc", ExtIPs: endpoint.Targets{"8.8.8.8"}},
				{SvcName: "delete-svc", ExtIPs: endpoint.Targets{"4.3.2.1"}},
			},
		},
	)

	r, err := registry.NewNoopRegistry(provider)
	require.NoError(t, err)

	fwr, err := fwregistry.NewRegistry(fwprovider)
	require.NoError(t, err)

	eipr, err := eipregistry.NewRegistry(eipprovider)

	// Run our controller once to trigger the validation.
	ctrl := &Controller{
		Source:      source,
		Registry:    r,
		FwRegistry:  fwr,
		EipRegistry: eipr,
		Policy:      &plan.SyncPolicy{},
	}

	assert.NoError(t, ctrl.RunOnce())

	// Validate that the mock source was called.
	source.AssertExpectations(t)
}
