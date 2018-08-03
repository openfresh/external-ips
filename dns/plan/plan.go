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
	"strings"

	"github.com/openfresh/external-ips/dns/endpoint"
)

// Plan can convert a list of desired and current records to a series of create,
// update and delete actions.
type Plan struct {
	// List of current records
	Current []*endpoint.Endpoint
	// List of desired records
	Desired []*endpoint.Endpoint
	// Policies under which the desired changes are calculated
	Policies []Policy
	// List of changes necessary to move towards desired state
	// Populated after calling Calculate()
	Changes *Changes
}

// Changes holds lists of actions to be executed by dns providers
type Changes struct {
	// Records that need to be created
	Create []*endpoint.Endpoint
	// Records that need to be updated (current data)
	UpdateOld []*endpoint.Endpoint
	// Records that need to be updated (desired data)
	UpdateNew []*endpoint.Endpoint
	// Records that need to be deleted
	Delete []*endpoint.Endpoint
}

// planTable is a supplementary struct for Plan
// each row correspond to a dnsName -> (current record + all desired records)
/*
planTable: (-> = target)
--------------------------------------------------------
DNSName | Current record | Desired Records             |
--------------------------------------------------------
foo.com | -> 1.1.1.1     | [->1.1.1.1, ->elb.com]      |  = no action
--------------------------------------------------------
bar.com |                | [->191.1.1.1, ->190.1.1.1]  |  = create (bar.com -> 190.1.1.1)
--------------------------------------------------------
"=", i.e. result of calculation relies on supplied ConflictResolver
*/
type planTable struct {
	rows     map[string]*planTableRow
	resolver ConflictResolver
}

func newPlanTable() planTable { //TODO: make resolver configurable
	return planTable{map[string]*planTableRow{}, PerResource{}}
}

// planTableRow
// current corresponds to the record currently occupying dns name on the dns provider
// candidates corresponds to the list of records which would like to have this dnsName
type planTableRow struct {
	current    *endpoint.Endpoint
	candidates []*endpoint.Endpoint
}

func (t planTable) addCurrent(e *endpoint.Endpoint) {
	dnsName := sanitizeDNSName(e.DNSName)
	if _, ok := t.rows[dnsName]; !ok {
		t.rows[dnsName] = &planTableRow{}
	}
	t.rows[dnsName].current = e
}

func (t planTable) addCandidate(e *endpoint.Endpoint) {
	dnsName := sanitizeDNSName(e.DNSName)
	if _, ok := t.rows[dnsName]; !ok {
		t.rows[dnsName] = &planTableRow{}
	}
	t.rows[dnsName].candidates = append(t.rows[dnsName].candidates, e)
}

// TODO: allows record type change, which might not be supported by all dns providers
func (t planTable) getUpdates() (updateNew []*endpoint.Endpoint, updateOld []*endpoint.Endpoint) {
	for _, row := range t.rows {
		if row.current != nil && len(row.candidates) > 0 { //dns name is taken
			update := t.resolver.ResolveUpdate(row.current, row.candidates)
			// compare "update" to "current" to figure out if actual update is required
			if shouldUpdateTTL(update, row.current) || targetChanged(update, row.current) {
				inheritOwner(row.current, update)
				updateNew = append(updateNew, update)
				updateOld = append(updateOld, row.current)
			}
			continue
		}
	}
	return
}

func (t planTable) getCreates() (createList []*endpoint.Endpoint) {
	for _, row := range t.rows {
		if row.current == nil { //dns name not taken
			createList = append(createList, t.resolver.ResolveCreate(row.candidates))
		}
	}
	return
}

func (t planTable) getDeletes() (deleteList []*endpoint.Endpoint) {
	for _, row := range t.rows {
		if row.current != nil && len(row.candidates) == 0 {
			deleteList = append(deleteList, row.current)
		}
	}
	return
}

// Calculate computes the actions needed to move current state towards desired
// state. It then passes those changes to the current policy for further
// processing. It returns a copy of Plan with the changes populated.
func (p *Plan) Calculate() *Plan {
	t := newPlanTable()

	for _, current := range p.Current {
		t.addCurrent(current)
	}
	for _, desired := range p.Desired {
		t.addCandidate(desired)
	}

	changes := &Changes{}
	changes.Create = t.getCreates()
	changes.Delete = t.getDeletes()
	changes.UpdateNew, changes.UpdateOld = t.getUpdates()
	for _, pol := range p.Policies {
		changes = pol.Apply(changes)
	}

	plan := &Plan{
		Current: p.Current,
		Desired: p.Desired,
		Changes: changes,
	}

	return plan
}

func inheritOwner(from, to *endpoint.Endpoint) {
	if to.Labels == nil {
		to.Labels = map[string]string{}
	}
	if from.Labels == nil {
		from.Labels = map[string]string{}
	}
	to.Labels[endpoint.OwnerLabelKey] = from.Labels[endpoint.OwnerLabelKey]
}

func targetChanged(desired, current *endpoint.Endpoint) bool {
	return !desired.Targets.Same(current.Targets)
}

func shouldUpdateTTL(desired, current *endpoint.Endpoint) bool {
	if !desired.RecordTTL.IsConfigured() {
		return false
	}
	return desired.RecordTTL != current.RecordTTL
}

// sanitizeDNSName checks if the DNS name is correct
// for now it only removes space and lower case
func sanitizeDNSName(dnsName string) string {
	return strings.TrimSpace(strings.ToLower(dnsName))
}
