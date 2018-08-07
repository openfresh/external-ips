// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package registry

import (
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/firewall/plan"
	"github.com/openfresh/external-ips/firewall/provider"
)

// RegistryImpl implements registry interface
type Registry struct {
	provider provider.Provider
}

// NewRegistry returns new Registry object
func NewRegistry(provider provider.Provider) (*Registry, error) {
	return &Registry{
		provider: provider,
	}, nil
}

// Rules returns the current rules from the firewall provider
func (im *Registry) Rules() ([]*inbound.InboundRules, error) {
	return im.provider.Rules()
}

// ApplyChanges propagates changes to the firewall provider
func (im *Registry) ApplyChanges(changes *plan.Changes) error {
	return im.provider.ApplyChanges(changes)
}
