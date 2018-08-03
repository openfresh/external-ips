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

package plan

import (
	"testing"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PlanTestSuite struct {
	suite.Suite
	fooV1Cname             *endpoint.Endpoint
	fooV2Cname             *endpoint.Endpoint
	fooV2CnameNoLabel      *endpoint.Endpoint
	fooV3CnameSameResource *endpoint.Endpoint
	fooA5                  *endpoint.Endpoint
	bar127A                *endpoint.Endpoint
	bar127AWithTTL         *endpoint.Endpoint
	bar192A                *endpoint.Endpoint
}

func (suite *PlanTestSuite) SetupTest() {
	suite.fooV1Cname = &endpoint.Endpoint{
		DNSName:    "foo",
		Targets:    endpoint.Targets{"v1"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	// same resource as fooV1Cname, but target is different. It will never be picked because its target lexicographically bigger than "v1"
	suite.fooV3CnameSameResource = &endpoint.Endpoint{ // TODO: remove this once endpoint can support multiple targets
		DNSName:    "foo",
		Targets:    endpoint.Targets{"v3"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	suite.fooV2Cname = &endpoint.Endpoint{
		DNSName:    "foo",
		Targets:    endpoint.Targets{"v2"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v2",
		},
	}
	suite.fooV2CnameNoLabel = &endpoint.Endpoint{
		DNSName:    "foo",
		Targets:    endpoint.Targets{"v2"},
		RecordType: "CNAME",
	}
	suite.fooA5 = &endpoint.Endpoint{
		DNSName:    "foo",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-5",
		},
	}
	suite.bar127A = &endpoint.Endpoint{
		DNSName:    "bar",
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
	}
	suite.bar127AWithTTL = &endpoint.Endpoint{
		DNSName:    "bar",
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		RecordTTL:  300,
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
	}
	suite.bar192A = &endpoint.Endpoint{
		DNSName:    "bar",
		Targets:    endpoint.Targets{"192.168.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-192",
		},
	}
}

func (suite *PlanTestSuite) TestSyncFirstRound() {
	current := []*endpoint.Endpoint{}
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV2Cname, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar127A} //v1 is chosen because of resolver taking "min"
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRound() {
	current := []*endpoint.Endpoint{suite.fooV1Cname}
	desired := []*endpoint.Endpoint{suite.fooV2Cname, suite.fooV1Cname, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundMigration() {
	current := []*endpoint.Endpoint{suite.fooV2CnameNoLabel}
	desired := []*endpoint.Endpoint{suite.fooV2Cname, suite.fooV1Cname, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV2CnameNoLabel}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithTTLChange() {
	current := []*endpoint.Endpoint{suite.bar127A}
	desired := []*endpoint.Endpoint{suite.bar127AWithTTL}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateNew := []*endpoint.Endpoint{suite.bar127AWithTTL}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithOwnerInherited() {
	current := []*endpoint.Endpoint{suite.fooV1Cname}
	desired := []*endpoint.Endpoint{suite.fooV2Cname}

	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedUpdateNew := []*endpoint.Endpoint{{
		DNSName:    suite.fooV2Cname.DNSName,
		Targets:    suite.fooV2Cname.Targets,
		RecordType: suite.fooV2Cname.RecordType,
		RecordTTL:  suite.fooV2Cname.RecordTTL,
		Labels: map[string]string{
			endpoint.ResourceLabelKey: suite.fooV2Cname.Labels[endpoint.ResourceLabelKey],
			endpoint.OwnerLabelKey:    suite.fooV1Cname.Labels[endpoint.OwnerLabelKey],
		},
	}}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestIdempotency() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV2Cname}
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV2Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestDifferentTypes() {
	current := []*endpoint.Endpoint{suite.fooV1Cname}
	desired := []*endpoint.Endpoint{suite.fooV2Cname, suite.fooA5}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooA5}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestRemoveEndpoint() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestRemoveEndpointWithUpsert() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&UpsertOnlyPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

//TODO: remove once multiple-target per endpoint is supported
func (suite *PlanTestSuite) TestDuplicatedEndpointsForSameResourceReplace() {
	current := []*endpoint.Endpoint{suite.fooV3CnameSameResource, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV3CnameSameResource}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV3CnameSameResource}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

//TODO: remove once multiple-target per endpoint is supported
func (suite *PlanTestSuite) TestDuplicatedEndpointsForSameResourceRetain() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV3CnameSameResource}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	changes := p.Calculate().Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func TestPlan(t *testing.T) {
	suite.Run(t, new(PlanTestSuite))
}

// validateEntries validates that the list of entries matches expected.
func validateEntries(t *testing.T, entries, expected []*endpoint.Endpoint) {
	if !testutils.SameEndpoints(entries, expected) {
		t.Fatalf("expected %q to match %q", entries, expected)
	}
}

func TestSanitizeDNSName(t *testing.T) {
	records := []struct {
		dnsName string
		expect  string
	}{
		{
			"3AAAA.FOO.BAR.COM    ",
			"3aaaa.foo.bar.com",
		},
		{
			"   example.foo.com",
			"example.foo.com",
		},
		{
			"example123.foo.com ",
			"example123.foo.com",
		},
		{
			"foo",
			"foo",
		},
		{
			"123foo.bar",
			"123foo.bar",
		},
		{
			"foo.com",
			"foo.com",
		},
		{
			"foo123.COM",
			"foo123.com",
		},
		{
			"my-exaMple3.FOO.BAR.COM",
			"my-example3.foo.bar.com",
		},
		{
			"   my-example1214.FOO-1235.BAR-foo.COM   ",
			"my-example1214.foo-1235.bar-foo.com",
		},
		{
			"my-example-my-example-1214.FOO-1235.BAR-foo.COM",
			"my-example-my-example-1214.foo-1235.bar-foo.com",
		},
	}
	for _, r := range records {
		gotName := sanitizeDNSName(r.dnsName)
		assert.Equal(t, r.expect, gotName)
	}
}
