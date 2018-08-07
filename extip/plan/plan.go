// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package plan

import (
	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/extip/extip"
)

type Plan struct {
	// List of current records
	Current []*extip.ExtIP
	// List of desired records
	Desired []*extip.ExtIP
	// List of changes necessary to move towards desired state
	// Populated after calling Calculate()
	Changes *Changes
}

// Changes holds lists of actions to be executed by dns providers
type Changes struct {
	// ExternaIPs that need to be updated (current data)
	UpdateOld []*extip.ExtIP
	// ExternaIPs that need to be updated (desired data)
	UpdateNew []*extip.ExtIP
}

type planTable struct {
	rows map[string]*planTableRow
}

func newPlanTable() planTable { //TODO: make resolver configurable
	return planTable{map[string]*planTableRow{}}
}

// planTableRow
// current corresponds to the record currently occupying dns name on the dns provider
// candidates corresponds to the list of records which would like to have this dnsName
type planTableRow struct {
	current   *extip.ExtIP
	candidate *extip.ExtIP
}

func (t planTable) addCurrent(e *extip.ExtIP) {
	if _, ok := t.rows[e.SvcName]; !ok {
		t.rows[e.SvcName] = &planTableRow{}
	}
	t.rows[e.SvcName].current = e
}

func (t planTable) addCandidate(e *extip.ExtIP) {
	if _, ok := t.rows[e.SvcName]; !ok {
		t.rows[e.SvcName] = &planTableRow{}
	}
	t.rows[e.SvcName].candidate = e
}

// TODO: allows record type change, which might not be supported by all dns providers
func (t planTable) getUpdates() (updateNew []*extip.ExtIP, updateOld []*extip.ExtIP) {
	for _, row := range t.rows {
		// compare "update" to "current" to figure out if actual update is required
		if row.current == nil {
			continue
		}
		if row.candidate == nil {
			row.candidate = &extip.ExtIP{
				SvcName: row.current.SvcName,
				ExtIPs:  endpoint.Targets{},
			}
		}
		if extipChanged(row.candidate, row.current) {
			updateNew = append(updateNew, row.candidate)
			updateOld = append(updateOld, row.current)
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
	changes.UpdateNew, changes.UpdateOld = t.getUpdates()

	plan := &Plan{
		Current: p.Current,
		Desired: p.Desired,
		Changes: changes,
	}

	return plan
}

func extipChanged(desired, current *extip.ExtIP) bool {
	return !desired.ExtIPs.Same(current.ExtIPs)
}
