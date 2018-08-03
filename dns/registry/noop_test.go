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

package registry

import (
	"testing"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/dns/plan"
	"github.com/openfresh/external-ips/dns/provider"
	"github.com/openfresh/external-ips/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Registry = &NoopRegistry{}

func TestNoopRegistry(t *testing.T) {
	t.Run("NewNoopRegistry", testNoopInit)
	t.Run("Records", testNoopRecords)
	t.Run("ApplyChanges", testNoopApplyChanges)
}

func testNoopInit(t *testing.T) {
	p := provider.NewInMemoryProvider()
	r, err := NewNoopRegistry(p)
	require.NoError(t, err)
	assert.Equal(t, p, r.provider)
}

func testNoopRecords(t *testing.T) {
	p := provider.NewInMemoryProvider()
	p.CreateZone("org")
	providerRecords := []*endpoint.Endpoint{
		{
			DNSName:    "example.org",
			Targets:    endpoint.Targets{"example-lb.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
	}
	p.ApplyChanges(&plan.Changes{
		Create: providerRecords,
	})

	r, _ := NewNoopRegistry(p)

	eps, err := r.Records()
	require.NoError(t, err)
	assert.True(t, testutils.SameEndpoints(eps, providerRecords))
}

func testNoopApplyChanges(t *testing.T) {
	// do some prep
	p := provider.NewInMemoryProvider()
	p.CreateZone("org")
	providerRecords := []*endpoint.Endpoint{
		{
			DNSName:    "example.org",
			Targets:    endpoint.Targets{"old-lb.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
	}
	expectedUpdate := []*endpoint.Endpoint{
		{
			DNSName:    "example.org",
			Targets:    endpoint.Targets{"new-example-lb.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
		{
			DNSName:    "new-record.org",
			Targets:    endpoint.Targets{"new-lb.org"},
			RecordType: endpoint.RecordTypeCNAME,
		},
	}

	p.ApplyChanges(&plan.Changes{
		Create: providerRecords,
	})

	// wrong changes
	r, _ := NewNoopRegistry(p)
	err := r.ApplyChanges(&plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "example.org",
				Targets:    endpoint.Targets{"lb.com"},
				RecordType: endpoint.RecordTypeCNAME,
			},
		},
	})
	assert.EqualError(t, err, provider.ErrRecordAlreadyExists.Error())

	//correct changes
	require.NoError(t, r.ApplyChanges(&plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "new-record.org",
				Targets:    endpoint.Targets{"new-lb.org"},
				RecordType: endpoint.RecordTypeCNAME,
			},
		},
		UpdateNew: []*endpoint.Endpoint{
			{
				DNSName:    "example.org",
				Targets:    endpoint.Targets{"new-example-lb.com"},
				RecordType: endpoint.RecordTypeCNAME,
			},
		},
		UpdateOld: []*endpoint.Endpoint{
			{
				DNSName:    "example.org",
				Targets:    endpoint.Targets{"old-lb.com"},
				RecordType: endpoint.RecordTypeCNAME,
			},
		},
	}))
	res, _ := p.Records()
	assert.True(t, testutils.SameEndpoints(res, expectedUpdate))
}
