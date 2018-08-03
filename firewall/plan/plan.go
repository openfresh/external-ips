// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package plan

import (
	"github.com/openfresh/external-ips/firewall/inbound"
)

type Plan struct {
	// List of current rules
	Current []*inbound.InboundRules
	// List of desired rules
	Desired []*inbound.InboundRules
	// List of changes necessary to move towards desired state
	// Populated after calling Calculate()
	Changes *Changes
}

type InstanceRule struct {
	ProviderID string
	RulesName  string
}

type Changes struct {
	// Rules that need to be created
	Create []*inbound.InboundRules
	// Rules that need to be updated (current data)
	UpdateOld []*inbound.InboundRules
	// Rules that need to be updated (desired data)
	UpdateNew []*inbound.InboundRules
	// Rules that need to be deleted
	Delete []*inbound.InboundRules

	Set   []*InstanceRule
	Unset []*InstanceRule
}

type planTable struct {
	rows map[string]*planTableRow
}

func newPlanTable() planTable { //TODO: make resolver configurable
	return planTable{map[string]*planTableRow{}}
}

type planTableRow struct {
	current   *inbound.InboundRules
	candidate *inbound.InboundRules
}

func (t planTable) addCurrent(r *inbound.InboundRules) {
	if _, ok := t.rows[r.Name]; !ok {
		t.rows[r.Name] = &planTableRow{}
	}
	t.rows[r.Name].current = r
}

func (t planTable) addCandidate(r *inbound.InboundRules) {
	if _, ok := t.rows[r.Name]; !ok {
		t.rows[r.Name] = &planTableRow{}
	}
	t.rows[r.Name].candidate = r
}

type planTable2 struct {
	rows map[string]*planTable2Row
}

func newPlanTable2() planTable2 { //TODO: make resolver configurable
	return planTable2{map[string]*planTable2Row{}}
}

type planTable2Row struct {
	current   *InstanceRule
	candidate *InstanceRule
}

func (t planTable2) addCurrent(i *InstanceRule) {
	if _, ok := t.rows[i.ProviderID+i.RulesName]; !ok {
		t.rows[i.ProviderID+i.RulesName] = &planTable2Row{}
	}
	t.rows[i.ProviderID+i.RulesName].current = i
}

func (t planTable2) addCandidate(i *InstanceRule) {
	if _, ok := t.rows[i.ProviderID+i.RulesName]; !ok {
		t.rows[i.ProviderID+i.RulesName] = &planTable2Row{}
	}
	t.rows[i.ProviderID+i.RulesName].candidate = i
}

func (t planTable) getUpdates() (updateNew []*inbound.InboundRules, updateOld []*inbound.InboundRules) {
	for _, row := range t.rows {
		if row.current != nil && row.candidate != nil {
			if !row.current.Same(row.current) {
				updateNew = append(updateNew, row.candidate)
				updateOld = append(updateOld, row.current)
			}
			continue
		}
	}
	return
}

func (t planTable) getCreates() (createList []*inbound.InboundRules) {
	for _, row := range t.rows {
		if row.current == nil {
			createList = append(createList, row.candidate)
		}
	}
	return
}

func (t planTable) getDeletes() (deleteList []*inbound.InboundRules) {
	for _, row := range t.rows {
		if row.current != nil && row.candidate == nil {
			deleteList = append(deleteList, row.current)
		}
	}
	return
}

func (t planTable2) getSets() (setList []*InstanceRule) {
	for _, row := range t.rows {
		if row.current == nil {
			setList = append(setList, row.candidate)
		}
	}
	return
}

func (t planTable2) getUnsets() (unsetList []*InstanceRule) {
	for _, row := range t.rows {
		if row.current != nil && row.candidate == nil {
			unsetList = append(unsetList, row.current)
		}
	}
	return
}

// Calculate computes the actions needed to move current state towards desired
// state. It then passes those changes to the current policy for further
// processing. It returns a copy of Plan with the changes populated.
func (p *Plan) Calculate() *Plan {
	t := newPlanTable()
	t2 := newPlanTable2()

	for _, current := range p.Current {
		t.addCurrent(current)
		for _, id := range current.ProviderIDs {
			ir := InstanceRule{
				ProviderID: id,
				RulesName:  current.Name,
			}
			t2.addCurrent(&ir)
		}
	}
	for _, desired := range p.Desired {
		t.addCandidate(desired)
		for _, id := range desired.ProviderIDs {
			ir := InstanceRule{
				ProviderID: id,
				RulesName:  desired.Name,
			}
			t2.addCandidate(&ir)
		}
	}

	changes := &Changes{}
	changes.Create = t.getCreates()
	changes.Delete = t.getDeletes()
	changes.UpdateNew, changes.UpdateOld = t.getUpdates()
	changes.Set = t2.getSets()
	changes.Unset = t2.getUnsets()

	plan := &Plan{
		Current: p.Current,
		Desired: p.Desired,
		Changes: changes,
	}

	return plan
}
