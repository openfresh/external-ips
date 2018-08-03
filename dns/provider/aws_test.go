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

package provider

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/dns/plan"
	"github.com/openfresh/external-ips/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultMaxChangeCount       = 4000
	defaultEvaluateTargetHealth = true
)

// Compile time check for interface conformance
var _ Route53API = &Route53APIStub{}

// Route53APIStub is a minimal implementation of Route53API, used primarily for unit testing.
// See http://http://docs.aws.amazon.com/sdk-for-go/api/service/route53.html for descriptions
// of all of its methods.
// mostly taken from: https://github.com/kubernetes/kubernetes/blob/853167624edb6bc0cfdcdfb88e746e178f5db36c/federation/pkg/dnsprovider/providers/aws/route53/stubs/route53api.go
type Route53APIStub struct {
	zones      map[string]*route53.HostedZone
	recordSets map[string]map[string][]*route53.ResourceRecordSet
}

// NewRoute53APIStub returns an initialized Route53APIStub
func NewRoute53APIStub() *Route53APIStub {
	return &Route53APIStub{
		zones:      make(map[string]*route53.HostedZone),
		recordSets: make(map[string]map[string][]*route53.ResourceRecordSet),
	}
}

func (r *Route53APIStub) ListResourceRecordSetsPages(input *route53.ListResourceRecordSetsInput, fn func(p *route53.ListResourceRecordSetsOutput, lastPage bool) (shouldContinue bool)) error {
	output := route53.ListResourceRecordSetsOutput{} // TODO: Support optional input args.
	if len(r.recordSets) <= 0 {
		output.ResourceRecordSets = []*route53.ResourceRecordSet{}
	} else if _, ok := r.recordSets[aws.StringValue(input.HostedZoneId)]; !ok {
		output.ResourceRecordSets = []*route53.ResourceRecordSet{}
	} else {
		for _, rrsets := range r.recordSets[aws.StringValue(input.HostedZoneId)] {
			for _, rrset := range rrsets {
				output.ResourceRecordSets = append(output.ResourceRecordSets, rrset)
			}
		}
	}
	lastPage := true
	fn(&output, lastPage)
	return nil
}

// Route53 stores wildcards escaped: http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html?shortFooter=true#domain-name-format-asterisk
func wildcardEscape(s string) string {
	if strings.HasPrefix(s, "*") {
		s = strings.Replace(s, "*", "\\052", 1)
	}
	return s
}

func (r *Route53APIStub) ChangeResourceRecordSets(input *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
	_, ok := r.zones[aws.StringValue(input.HostedZoneId)]
	if !ok {
		return nil, fmt.Errorf("Hosted zone doesn't exist: %s", aws.StringValue(input.HostedZoneId))
	}

	if len(input.ChangeBatch.Changes) == 0 {
		return nil, fmt.Errorf("ChangeBatch doesn't contain any changes")
	}

	output := &route53.ChangeResourceRecordSetsOutput{}
	recordSets, ok := r.recordSets[aws.StringValue(input.HostedZoneId)]
	if !ok {
		recordSets = make(map[string][]*route53.ResourceRecordSet)
	}

	for _, change := range input.ChangeBatch.Changes {
		if aws.StringValue(change.ResourceRecordSet.Type) == route53.RRTypeA {
			for _, rrs := range change.ResourceRecordSet.ResourceRecords {
				if net.ParseIP(aws.StringValue(rrs.Value)) == nil {
					return nil, fmt.Errorf("A records must point to IPs")
				}
			}
		}

		change.ResourceRecordSet.Name = aws.String(wildcardEscape(ensureTrailingDot(aws.StringValue(change.ResourceRecordSet.Name))))

		if change.ResourceRecordSet.AliasTarget != nil {
			change.ResourceRecordSet.AliasTarget.DNSName = aws.String(wildcardEscape(ensureTrailingDot(aws.StringValue(change.ResourceRecordSet.AliasTarget.DNSName))))
		}

		key := aws.StringValue(change.ResourceRecordSet.Name) + "::" + aws.StringValue(change.ResourceRecordSet.Type)
		switch aws.StringValue(change.Action) {
		case route53.ChangeActionCreate:
			if _, found := recordSets[key]; found {
				return nil, fmt.Errorf("Attempt to create duplicate rrset %s", key) // TODO: Return AWS errors with codes etc
			}
			recordSets[key] = append(recordSets[key], change.ResourceRecordSet)
		case route53.ChangeActionDelete:
			if _, found := recordSets[key]; !found {
				return nil, fmt.Errorf("Attempt to delete non-existent rrset %s", key) // TODO: Check other fields too
			}
			delete(recordSets, key)
		case route53.ChangeActionUpsert:
			recordSets[key] = []*route53.ResourceRecordSet{change.ResourceRecordSet}
		}
	}
	r.recordSets[aws.StringValue(input.HostedZoneId)] = recordSets
	return output, nil // TODO: We should ideally return status etc, but we don't' use that yet.
}

func (r *Route53APIStub) ListHostedZonesPages(input *route53.ListHostedZonesInput, fn func(p *route53.ListHostedZonesOutput, lastPage bool) (shouldContinue bool)) error {
	output := &route53.ListHostedZonesOutput{}
	for _, zone := range r.zones {
		output.HostedZones = append(output.HostedZones, zone)
	}
	lastPage := true
	fn(output, lastPage)
	return nil
}

func (r *Route53APIStub) CreateHostedZone(input *route53.CreateHostedZoneInput) (*route53.CreateHostedZoneOutput, error) {
	name := aws.StringValue(input.Name)
	id := "/hostedzone/" + name
	if _, ok := r.zones[id]; ok {
		return nil, fmt.Errorf("Error creating hosted DNS zone: %s already exists", id)
	}
	r.zones[id] = &route53.HostedZone{
		Id:     aws.String(id),
		Name:   aws.String(name),
		Config: input.HostedZoneConfig,
	}
	return &route53.CreateHostedZoneOutput{HostedZone: r.zones[id]}, nil
}

func TestAWSZones(t *testing.T) {
	publicZones := map[string]*route53.HostedZone{
		"/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do.": {
			Id:   aws.String("/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do."),
			Name: aws.String("zone-1.ext-dns-test-2.teapot.zalan.do."),
		},
		"/hostedzone/zone-2.ext-dns-test-2.teapot.zalan.do.": {
			Id:   aws.String("/hostedzone/zone-2.ext-dns-test-2.teapot.zalan.do."),
			Name: aws.String("zone-2.ext-dns-test-2.teapot.zalan.do."),
		},
	}

	privateZones := map[string]*route53.HostedZone{
		"/hostedzone/zone-3.ext-dns-test-2.teapot.zalan.do.": {
			Id:   aws.String("/hostedzone/zone-3.ext-dns-test-2.teapot.zalan.do."),
			Name: aws.String("zone-3.ext-dns-test-2.teapot.zalan.do."),
		},
	}

	allZones := map[string]*route53.HostedZone{}
	for k, v := range publicZones {
		allZones[k] = v
	}
	for k, v := range privateZones {
		allZones[k] = v
	}

	noZones := map[string]*route53.HostedZone{}

	for _, ti := range []struct {
		msg            string
		zoneIDFilter   ZoneIDFilter
		zoneTypeFilter ZoneTypeFilter
		expectedZones  map[string]*route53.HostedZone
	}{
		{"no filter", NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), allZones},
		{"public filter", NewZoneIDFilter([]string{}), NewZoneTypeFilter("public"), publicZones},
		{"private filter", NewZoneIDFilter([]string{}), NewZoneTypeFilter("private"), privateZones},
		{"unknown filter", NewZoneIDFilter([]string{}), NewZoneTypeFilter("unknown"), noZones},
		{"zone id filter", NewZoneIDFilter([]string{"/hostedzone/zone-3.ext-dns-test-2.teapot.zalan.do."}), NewZoneTypeFilter(""), privateZones},
	} {
		provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), ti.zoneIDFilter, ti.zoneTypeFilter, defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{})

		zones, err := provider.Zones()
		require.NoError(t, err)

		validateAWSZones(t, zones, ti.expectedZones)
	}
}

func TestAWSRecords(t *testing.T) {
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("list-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("list-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("*.wildcard-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpoint("list-test-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpoint("*.wildcard-test-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("list-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
	})

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("list-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("list-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("*.wildcard-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpoint("list-test-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpoint("*.wildcard-test-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("list-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
	})
}

func TestAWSCreateRecords(t *testing.T) {
	customTTL := endpoint.TTL(60)
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{})

	records := []*endpoint.Endpoint{
		endpoint.NewEndpoint("create-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("create-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpointWithTTL("create-test-cname-custom-ttl.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, customTTL, "172.17.0.1"),
		endpoint.NewEndpoint("create-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}

	require.NoError(t, provider.CreateRecords(records))

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("create-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("create-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("create-test-cname-custom-ttl.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, customTTL, "172.17.0.1"),
		endpoint.NewEndpointWithTTL("create-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "foo.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
	})
}

func TestAWSUpdateRecords(t *testing.T) {
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "foo.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
	})

	currentRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}
	updatedRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "4.3.2.1"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "bar.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4", "4.3.2.1"),
	}

	require.NoError(t, provider.UpdateRecords(updatedRecords, currentRecords))

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "4.3.2.1"),
		endpoint.NewEndpointWithTTL("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "bar.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("create-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4", "4.3.2.1"),
	})
}

func TestAWSDeleteRecords(t *testing.T) {
	originalEndpoints := []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("delete-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("delete-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "baz.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.eu-central-1.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("delete-test-multiple.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
	}

	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, originalEndpoints)

	require.NoError(t, provider.DeleteRecords(originalEndpoints))

	records, err := provider.Records()

	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{})
}

func TestAWSApplyChanges(t *testing.T) {
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("delete-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("delete-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "bar.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "qux.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "bar.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("delete-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "qux.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
		endpoint.NewEndpointWithTTL("delete-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4", "4.3.2.1"),
	})

	createRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("create-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("create-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("create-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}

	currentRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "bar.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "bar.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}
	updatedRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "4.3.2.1"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "baz.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "baz.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4", "4.3.2.1"),
	}

	deleteRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("delete-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("delete-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "qux.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "qux.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4", "4.3.2.1"),
	}

	changes := &plan.Changes{
		Create:    createRecords,
		UpdateNew: updatedRecords,
		UpdateOld: currentRecords,
		Delete:    deleteRecords,
	}

	require.NoError(t, provider.ApplyChanges(changes))

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("create-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4"),
		endpoint.NewEndpointWithTTL("create-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "4.3.2.1"),
		endpoint.NewEndpointWithTTL("create-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "foo.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "baz.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("create-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "foo.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "baz.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("create-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
		endpoint.NewEndpointWithTTL("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4", "4.3.2.1"),
	})
}

func TestAWSApplyChangesDryRun(t *testing.T) {
	originalEndpoints := []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("delete-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8"),
		endpoint.NewEndpointWithTTL("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("delete-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.4.4"),
		endpoint.NewEndpointWithTTL("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "bar.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "qux.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "bar.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("delete-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, endpoint.TTL(recordTTL), "qux.elb.amazonaws.com"),
		endpoint.NewEndpointWithTTL("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "8.8.8.8", "8.8.4.4"),
		endpoint.NewEndpointWithTTL("delete-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, endpoint.TTL(recordTTL), "1.2.3.4", "4.3.2.1"),
	}

	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, true, originalEndpoints)

	createRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("create-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("create-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("create-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "foo.elb.amazonaws.com"),
		endpoint.NewEndpoint("create-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}

	currentRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "bar.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "bar.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8", "8.8.4.4"),
	}
	updatedRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("update-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4"),
		endpoint.NewEndpoint("update-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "4.3.2.1"),
		endpoint.NewEndpoint("update-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "baz.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "baz.elb.amazonaws.com"),
		endpoint.NewEndpoint("update-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4", "4.3.2.1"),
	}

	deleteRecords := []*endpoint.Endpoint{
		endpoint.NewEndpoint("delete-test.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.8.8"),
		endpoint.NewEndpoint("delete-test.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "8.8.4.4"),
		endpoint.NewEndpoint("delete-test-cname.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "qux.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-cname-alias.zone-1.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeCNAME, "qux.elb.amazonaws.com"),
		endpoint.NewEndpoint("delete-test-multiple.zone-2.ext-dns-test-2.teapot.zalan.do", endpoint.RecordTypeA, "1.2.3.4", "4.3.2.1"),
	}

	changes := &plan.Changes{
		Create:    createRecords,
		UpdateNew: updatedRecords,
		UpdateOld: currentRecords,
		Delete:    deleteRecords,
	}

	require.NoError(t, provider.ApplyChanges(changes))

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, originalEndpoints)
}

func TestAWSChangesByZones(t *testing.T) {
	changes := []*route53.Change{
		{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("qux.foo.example.org"), TTL: aws.Int64(1),
			},
		},
		{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("qux.bar.example.org"), TTL: aws.Int64(2),
			},
		},
		{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("wambo.foo.example.org"), TTL: aws.Int64(10),
			},
		},
		{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("wambo.bar.example.org"), TTL: aws.Int64(20),
			},
		},
	}

	zones := map[string]*route53.HostedZone{
		"foo-example-org": {
			Id:   aws.String("foo-example-org"),
			Name: aws.String("foo.example.org."),
		},
		"bar-example-org": {
			Id:   aws.String("bar-example-org"),
			Name: aws.String("bar.example.org."),
		},
		"bar-example-org-private": {
			Id:     aws.String("bar-example-org-private"),
			Name:   aws.String("bar.example.org."),
			Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(true)},
		},
		"baz-example-org": {
			Id:   aws.String("baz-example-org"),
			Name: aws.String("baz.example.org."),
		},
	}

	changesByZone := changesByZone(zones, changes)
	require.Len(t, changesByZone, 3)

	validateAWSChangeRecords(t, changesByZone["foo-example-org"], []*route53.Change{
		{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("qux.foo.example.org"), TTL: aws.Int64(1),
			},
		},
		{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("wambo.foo.example.org"), TTL: aws.Int64(10),
			},
		},
	})

	validateAWSChangeRecords(t, changesByZone["bar-example-org"], []*route53.Change{
		{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("qux.bar.example.org"), TTL: aws.Int64(2),
			},
		},
		{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("wambo.bar.example.org"), TTL: aws.Int64(20),
			},
		},
	})

	validateAWSChangeRecords(t, changesByZone["bar-example-org-private"], []*route53.Change{
		{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("qux.bar.example.org"), TTL: aws.Int64(2),
			},
		},
		{
			Action: aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String("wambo.bar.example.org"), TTL: aws.Int64(20),
			},
		},
	})
}

func TestAWSsubmitChanges(t *testing.T) {
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{})
	const subnets = 16
	const hosts = defaultMaxChangeCount / subnets

	endpoints := make([]*endpoint.Endpoint, 0)
	for i := 0; i < subnets; i++ {
		for j := 1; j < (hosts + 1); j++ {
			hostname := fmt.Sprintf("subnet%dhost%d.zone-1.ext-dns-test-2.teapot.zalan.do", i, j)
			ip := fmt.Sprintf("1.1.%d.%d", i, j)
			ep := endpoint.NewEndpointWithTTL(hostname, endpoint.RecordTypeA, endpoint.TTL(recordTTL), ip)
			endpoints = append(endpoints, ep)
		}
	}

	cs := make([]*route53.Change, 0, len(endpoints))
	cs = append(cs, provider.newChanges(route53.ChangeActionCreate, endpoints)...)

	require.NoError(t, provider.submitChanges(cs))

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, endpoints)
}

func TestAWSLimitChangeSet(t *testing.T) {
	var cs []*route53.Change

	for i := 1; i <= defaultMaxChangeCount; i += 2 {
		cs = append(cs, &route53.Change{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(fmt.Sprintf("host-%d", i)),
				Type: aws.String("A"),
			},
		})
		cs = append(cs, &route53.Change{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(fmt.Sprintf("host-%d", i)),
				Type: aws.String("TXT"),
			},
		})
	}

	limCs := limitChangeSet(cs, defaultMaxChangeCount)

	// sorting cs not needed as it should be returned as is
	validateAWSChangeRecords(t, limCs, cs)
}

func TestAWSLimitChangeSetExceeding(t *testing.T) {
	var cs []*route53.Change
	const testCount = 100
	const testLimit = 11
	const expectedCount = 10

	for i := 1; i <= testCount; i += 2 {
		cs = append(cs, &route53.Change{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(fmt.Sprintf("host-%d", i)),
				Type: aws.String("A"),
			},
		})
		cs = append(cs, &route53.Change{
			Action: aws.String(route53.ChangeActionCreate),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(fmt.Sprintf("host-%d", i)),
				Type: aws.String("TXT"),
			},
		})
	}

	limCs := limitChangeSet(cs, testLimit)

	// sorting cs needed to match limCs
	validateAWSChangeRecords(t, limCs, sortChangesByActionNameType(cs)[0:expectedCount])
}

func validateEndpoints(t *testing.T, endpoints []*endpoint.Endpoint, expected []*endpoint.Endpoint) {
	assert.True(t, testutils.SameEndpoints(endpoints, expected), "expected and actual endpoints don't match. %s:%s", endpoints, expected)
}

func validateAWSZones(t *testing.T, zones map[string]*route53.HostedZone, expected map[string]*route53.HostedZone) {
	require.Len(t, zones, len(expected))

	for i, zone := range zones {
		validateAWSZone(t, zone, expected[i])
	}
}

func validateAWSZone(t *testing.T, zone *route53.HostedZone, expected *route53.HostedZone) {
	assert.Equal(t, aws.StringValue(expected.Id), aws.StringValue(zone.Id))
	assert.Equal(t, aws.StringValue(expected.Name), aws.StringValue(zone.Name))
}

func validateAWSChangeRecords(t *testing.T, records []*route53.Change, expected []*route53.Change) {
	require.Len(t, records, len(expected))

	for i := range records {
		validateAWSChangeRecord(t, records[i], expected[i])
	}
}

func validateAWSChangeRecord(t *testing.T, record *route53.Change, expected *route53.Change) {
	assert.Equal(t, aws.StringValue(expected.Action), aws.StringValue(record.Action))
	assert.Equal(t, aws.StringValue(expected.ResourceRecordSet.Name), aws.StringValue(record.ResourceRecordSet.Name))
	assert.Equal(t, aws.StringValue(expected.ResourceRecordSet.Type), aws.StringValue(record.ResourceRecordSet.Type))
}

func TestAWSCreateRecordsWithCNAME(t *testing.T) {
	provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), defaultEvaluateTargetHealth, false, []*endpoint.Endpoint{})

	records := []*endpoint.Endpoint{
		{DNSName: "create-test.zone-1.ext-dns-test-2.teapot.zalan.do", Targets: endpoint.Targets{"foo.example.org"}, RecordType: endpoint.RecordTypeCNAME},
	}

	require.NoError(t, provider.CreateRecords(records))

	recordSets := listAWSRecords(t, provider.client, "/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do.")

	validateRecords(t, recordSets, []*route53.ResourceRecordSet{
		{
			Name: aws.String("create-test.zone-1.ext-dns-test-2.teapot.zalan.do."),
			Type: aws.String(endpoint.RecordTypeCNAME),
			TTL:  aws.Int64(300),
			ResourceRecords: []*route53.ResourceRecord{
				{
					Value: aws.String("foo.example.org"),
				},
			},
		},
	})
}

func TestAWSCreateRecordsWithALIAS(t *testing.T) {
	for _, evaluateTargetHealth := range []bool{
		true,
		false,
	} {
		provider := newAWSProvider(t, NewDomainFilter([]string{"ext-dns-test-2.teapot.zalan.do."}), NewZoneIDFilter([]string{}), NewZoneTypeFilter(""), evaluateTargetHealth, false, []*endpoint.Endpoint{})

		records := []*endpoint.Endpoint{
			{DNSName: "create-test.zone-1.ext-dns-test-2.teapot.zalan.do", Targets: endpoint.Targets{"foo.eu-central-1.elb.amazonaws.com"}, RecordType: endpoint.RecordTypeCNAME},
		}

		require.NoError(t, provider.CreateRecords(records))

		recordSets := listAWSRecords(t, provider.client, "/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do.")

		validateRecords(t, recordSets, []*route53.ResourceRecordSet{
			{
				AliasTarget: &route53.AliasTarget{
					DNSName:              aws.String("foo.eu-central-1.elb.amazonaws.com."),
					EvaluateTargetHealth: aws.Bool(evaluateTargetHealth),
					HostedZoneId:         aws.String("Z215JYRZR1TBD5"),
				},
				Name: aws.String("create-test.zone-1.ext-dns-test-2.teapot.zalan.do."),
				Type: aws.String(endpoint.RecordTypeA),
			},
		})
	}
}

func TestAWSisLoadBalancer(t *testing.T) {
	for _, tc := range []struct {
		target     string
		recordType string
		expected   bool
	}{
		{"bar.eu-central-1.elb.amazonaws.com", endpoint.RecordTypeCNAME, true},
		{"foo.example.org", endpoint.RecordTypeCNAME, false},
	} {
		ep := &endpoint.Endpoint{
			Targets:    endpoint.Targets{tc.target},
			RecordType: tc.recordType,
		}
		assert.Equal(t, tc.expected, isAWSLoadBalancer(ep))
	}
}

func TestAWSCanonicalHostedZone(t *testing.T) {
	for _, tc := range []struct {
		hostname string
		expected string
	}{
		// Application Load Balancers and Classic Load Balancers
		{"foo.us-east-2.elb.amazonaws.com", "Z3AADJGX6KTTL2"},
		{"foo.us-east-1.elb.amazonaws.com", "Z35SXDOTRQ7X7K"},
		{"foo.us-west-1.elb.amazonaws.com", "Z368ELLRRE2KJ0"},
		{"foo.us-west-2.elb.amazonaws.com", "Z1H1FL5HABSF5"},
		{"foo.ca-central-1.elb.amazonaws.com", "ZQSVJUPU6J1EY"},
		{"foo.ap-south-1.elb.amazonaws.com", "ZP97RAFLXTNZK"},
		{"foo.ap-northeast-2.elb.amazonaws.com", "ZWKZPGTI48KDX"},
		{"foo.ap-northeast-3.elb.amazonaws.com", "Z5LXEXXYW11ES"},
		{"foo.ap-southeast-1.elb.amazonaws.com", "Z1LMS91P8CMLE5"},
		{"foo.ap-southeast-2.elb.amazonaws.com", "Z1GM3OXH4ZPM65"},
		{"foo.ap-northeast-1.elb.amazonaws.com", "Z14GRHDCWA56QT"},
		{"foo.eu-central-1.elb.amazonaws.com", "Z215JYRZR1TBD5"},
		{"foo.eu-west-1.elb.amazonaws.com", "Z32O12XQLNTSW2"},
		{"foo.eu-west-2.elb.amazonaws.com", "ZHURV8PSTC4K8"},
		{"foo.eu-west-3.elb.amazonaws.com", "Z3Q77PNBQS71R4"},
		{"foo.sa-east-1.elb.amazonaws.com", "Z2P70J7HTTTPLU"},
		// Network Load Balancers
		{"foo.elb.us-east-2.amazonaws.com", "ZLMOA37VPKANP"},
		{"foo.elb.us-east-1.amazonaws.com", "Z26RNL4JYFTOTI"},
		{"foo.elb.us-west-1.amazonaws.com", "Z24FKFUX50B4VW"},
		{"foo.elb.us-west-2.amazonaws.com", "Z18D5FSROUN65G"},
		{"foo.elb.ca-central-1.amazonaws.com", "Z2EPGBW3API2WT"},
		{"foo.elb.ap-south-1.amazonaws.com", "ZVDDRBQ08TROA"},
		{"foo.elb.ap-northeast-2.amazonaws.com", "ZIBE1TIR4HY56"},
		{"foo.elb.ap-southeast-1.amazonaws.com", "ZKVM4W9LS7TM"},
		{"foo.elb.ap-southeast-2.amazonaws.com", "ZCT6FZBF4DROD"},
		{"foo.elb.ap-northeast-1.amazonaws.com", "Z31USIVHYNEOWT"},
		{"foo.elb.eu-central-1.amazonaws.com", "Z3F0SRJ5LGBH90"},
		{"foo.elb.eu-west-1.amazonaws.com", "Z2IFOLAFXWLO4F"},
		{"foo.elb.eu-west-2.amazonaws.com", "ZD4D7Y8KGAS4G"},
		{"foo.elb.eu-west-3.amazonaws.com", "Z1CMS0P5QUZ6D5"},
		{"foo.elb.sa-east-1.amazonaws.com", "ZTK26PT1VY4CU"},
		// No Load Balancer
		{"foo.example.org", ""},
	} {
		zone := canonicalHostedZone(tc.hostname)
		assert.Equal(t, tc.expected, zone)
	}
}

func TestAWSSuitableZones(t *testing.T) {
	zones := map[string]*route53.HostedZone{
		// Public domain
		"example-org": {Id: aws.String("example-org"), Name: aws.String("example.org.")},
		// Public subdomain
		"bar-example-org": {Id: aws.String("bar-example-org"), Name: aws.String("bar.example.org."), Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(false)}},
		// Public subdomain
		"longfoo-bar-example-org": {Id: aws.String("longfoo-bar-example-org"), Name: aws.String("longfoo.bar.example.org.")},
		// Private domain
		"example-org-private": {Id: aws.String("example-org-private"), Name: aws.String("example.org."), Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(true)}},
		// Private subdomain
		"bar-example-org-private": {Id: aws.String("bar-example-org-private"), Name: aws.String("bar.example.org."), Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(true)}},
	}

	for _, tc := range []struct {
		hostname string
		expected []*route53.HostedZone
	}{
		// bar.example.org is NOT suitable
		{"foobar.example.org.", []*route53.HostedZone{zones["example-org-private"], zones["example-org"]}},

		// all matching private zones are suitable
		// https://github.com/kubernetes-incubator/external-dns/pull/356
		{"bar.example.org.", []*route53.HostedZone{zones["example-org-private"], zones["bar-example-org-private"], zones["bar-example-org"]}},

		{"foo.bar.example.org.", []*route53.HostedZone{zones["example-org-private"], zones["bar-example-org-private"], zones["bar-example-org"]}},
		{"foo.example.org.", []*route53.HostedZone{zones["example-org-private"], zones["example-org"]}},
		{"foo.kubernetes.io.", nil},
	} {
		suitableZones := suitableZones(tc.hostname, zones)
		sort.Slice(suitableZones, func(i, j int) bool { return *suitableZones[i].Id < *suitableZones[j].Id })
		sort.Slice(tc.expected, func(i, j int) bool { return *tc.expected[i].Id < *tc.expected[j].Id })
		assert.Equal(t, tc.expected, suitableZones)
	}
}

func createAWSZone(t *testing.T, provider *AWSProvider, zone *route53.HostedZone) {
	params := &route53.CreateHostedZoneInput{
		CallerReference:  aws.String("external-dns.alpha.kubernetes.io/test-zone"),
		Name:             zone.Name,
		HostedZoneConfig: zone.Config,
	}

	if _, err := provider.client.CreateHostedZone(params); err != nil {
		require.EqualError(t, err, route53.ErrCodeHostedZoneAlreadyExists)
	}
}

func setupAWSRecords(t *testing.T, provider *AWSProvider, endpoints []*endpoint.Endpoint) {
	clearAWSRecords(t, provider, "/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do.")
	clearAWSRecords(t, provider, "/hostedzone/zone-2.ext-dns-test-2.teapot.zalan.do.")
	clearAWSRecords(t, provider, "/hostedzone/zone-3.ext-dns-test-2.teapot.zalan.do.")

	records, err := provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, []*endpoint.Endpoint{})

	require.NoError(t, provider.CreateRecords(endpoints))

	records, err = provider.Records()
	require.NoError(t, err)

	validateEndpoints(t, records, endpoints)
}

func listAWSRecords(t *testing.T, client Route53API, zone string) []*route53.ResourceRecordSet {
	recordSets := []*route53.ResourceRecordSet{}
	require.NoError(t, client.ListResourceRecordSetsPages(&route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zone),
	}, func(resp *route53.ListResourceRecordSetsOutput, _ bool) bool {
		for _, recordSet := range resp.ResourceRecordSets {
			switch aws.StringValue(recordSet.Type) {
			case endpoint.RecordTypeA, endpoint.RecordTypeCNAME:
				recordSets = append(recordSets, recordSet)
			}
		}
		return true
	}))

	return recordSets
}

func clearAWSRecords(t *testing.T, provider *AWSProvider, zone string) {
	recordSets := listAWSRecords(t, provider.client, zone)

	changes := make([]*route53.Change, 0, len(recordSets))
	for _, recordSet := range recordSets {
		changes = append(changes, &route53.Change{
			Action:            aws.String(route53.ChangeActionDelete),
			ResourceRecordSet: recordSet,
		})
	}

	if len(changes) != 0 {
		_, err := provider.client.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(zone),
			ChangeBatch: &route53.ChangeBatch{
				Changes: changes,
			},
		})
		require.NoError(t, err)
	}
}

func newAWSProvider(t *testing.T, domainFilter DomainFilter, zoneIDFilter ZoneIDFilter, zoneTypeFilter ZoneTypeFilter, evaluateTargetHealth, dryRun bool, records []*endpoint.Endpoint) *AWSProvider {
	client := NewRoute53APIStub()

	provider := &AWSProvider{
		client:               client,
		maxChangeCount:       defaultMaxChangeCount,
		evaluateTargetHealth: evaluateTargetHealth,
		domainFilter:         domainFilter,
		zoneIDFilter:         zoneIDFilter,
		zoneTypeFilter:       zoneTypeFilter,
		dryRun:               false,
	}

	createAWSZone(t, provider, &route53.HostedZone{
		Id:     aws.String("/hostedzone/zone-1.ext-dns-test-2.teapot.zalan.do."),
		Name:   aws.String("zone-1.ext-dns-test-2.teapot.zalan.do."),
		Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(false)},
	})

	createAWSZone(t, provider, &route53.HostedZone{
		Id:     aws.String("/hostedzone/zone-2.ext-dns-test-2.teapot.zalan.do."),
		Name:   aws.String("zone-2.ext-dns-test-2.teapot.zalan.do."),
		Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(false)},
	})

	createAWSZone(t, provider, &route53.HostedZone{
		Id:     aws.String("/hostedzone/zone-3.ext-dns-test-2.teapot.zalan.do."),
		Name:   aws.String("zone-3.ext-dns-test-2.teapot.zalan.do."),
		Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(true)},
	})

	// filtered out by domain filter
	createAWSZone(t, provider, &route53.HostedZone{
		Id:     aws.String("/hostedzone/zone-4.ext-dns-test-3.teapot.zalan.do."),
		Name:   aws.String("zone-4.ext-dns-test-3.teapot.zalan.do."),
		Config: &route53.HostedZoneConfig{PrivateZone: aws.Bool(false)},
	})

	setupAWSRecords(t, provider, records)

	provider.dryRun = dryRun

	return provider
}

func validateRecords(t *testing.T, records []*route53.ResourceRecordSet, expected []*route53.ResourceRecordSet) {
	assert.Equal(t, expected, records)
}
