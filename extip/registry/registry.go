// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package registry

import (
	"github.com/openfresh/external-ips/extip/extip"
	"github.com/openfresh/external-ips/extip/plan"
	"github.com/openfresh/external-ips/extip/provider"
)

type Registry struct {
	provider provider.Provider
}

// NewRegistry returns new RegistryImpl object
func NewRegistry(provider provider.Provider) (*Registry, error) {
	return &Registry{
		provider: provider,
	}, nil
}

// ExtIPs returns the current extips from the cluster
func (im *Registry) ExtIPs() ([]*extip.ExtIP, error) {
	return im.provider.ExtIPs()
}

// ApplyChanges propagates changes to the cluster
func (im *Registry) ApplyChanges(changes *plan.Changes) error {
	return im.provider.ApplyChanges(changes)
}
