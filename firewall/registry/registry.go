// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package registry

import (
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/firewall/plan"
	"github.com/openfresh/external-ips/firewall/provider"
)

type Registry interface {
	Rules() ([]*inbound.InboundRules, error)
	ApplyChanges(changes *plan.Changes) error
}

// RegistryImpl implements registry interface
type RegistryImpl struct {
	provider provider.Provider
}

// NewRegistry returns new RegistryImpl object
func NewRegistry(provider provider.Provider) (*RegistryImpl, error) {
	return &RegistryImpl{
		provider: provider,
	}, nil
}

// Records returns the current records from the dns provider
func (im *RegistryImpl) Rules() ([]*inbound.InboundRules, error) {
	return im.provider.Rules()
}

// ApplyChanges propagates changes to the dns provider
func (im *RegistryImpl) ApplyChanges(changes *plan.Changes) error {
	return im.provider.ApplyChanges(changes)
}
