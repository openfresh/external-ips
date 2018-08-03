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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/openfresh/external-ips/dns/plan"
	"github.com/openfresh/external-ips/dns/registry"
	fwplan "github.com/openfresh/external-ips/firewall/plan"
	fwregistry "github.com/openfresh/external-ips/firewall/registry"
	"github.com/openfresh/external-ips/source"
)

// Controller is responsible for orchestrating the different components.
// It works in the following way:
// * Ask the DNS provider for current list of endpoints.
// * Ask the Source for the desired list of endpoints.
// * Take both lists and calculate a Plan to move current towards desired state.
// * Tell the DNS provider to apply the changes calucated by the Plan.
type Controller struct {
	Source     source.Source
	Registry   registry.Registry
	FwRegistry fwregistry.Registry
	// The policy that defines which changes to DNS records are allowed
	Policy plan.Policy
	// The interval between individual synchronizations
	Interval time.Duration
}

// RunOnce runs a single iteration of a reconciliation loop.
func (c *Controller) RunOnce() error {
	records, err := c.Registry.Records()
	if err != nil {
		return err
	}

	rules, err := c.FwRegistry.Rules()
	if err != nil {
		return err
	}

	setting, err := c.Source.ExternalIPSetting()
	if err != nil {
		return err
	}

	fwplan := &fwplan.Plan{
		Current: rules,
		Desired: setting.InboundRules,
	}

	fwplan = fwplan.Calculate()

	err = c.FwRegistry.ApplyChanges(fwplan.Changes)
	if err != nil {
		return err
	}

	plan := &plan.Plan{
		Policies: []plan.Policy{c.Policy},
		Current:  records,
		Desired:  setting.Endpoints,
	}

	plan = plan.Calculate()

	return c.Registry.ApplyChanges(plan.Changes)
}

// Run runs RunOnce in a loop with a delay until stopChan receives a value.
func (c *Controller) Run(stopChan <-chan struct{}) {
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		err := c.RunOnce()
		if err != nil {
			log.Error(err)
		}
		select {
		case <-ticker.C:
		case <-stopChan:
			log.Info("Terminating main controller loop")
			return
		}
	}
}
