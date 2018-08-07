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

package source

import (
	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/extip/extip"
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/setting"
)

// multiSource is a Source that merges the endpoints of its nested Sources.
type multiSource struct {
	children []Source
}

// Endpoints collects endpoints of all nested Sources and returns them in a single slice.
func (ms *multiSource) ExternalIPSetting() (*setting.ExternalIPSetting, error) {
	result := setting.ExternalIPSetting{
		Endpoints:    []*endpoint.Endpoint{},
		InboundRules: []*inbound.InboundRules{},
		ExtIPs:       []*extip.ExtIP{},
	}

	for _, s := range ms.children {
		setting, err := s.ExternalIPSetting()
		if err != nil {
			return nil, err
		}

		result.Endpoints = append(result.Endpoints, setting.Endpoints...)
		result.InboundRules = append(result.InboundRules, setting.InboundRules...)
		result.ExtIPs = append(result.ExtIPs, setting.ExtIPs...)
	}

	return &result, nil
}

// NewMultiSource creates a new multiSource.
func NewMultiSource(children []Source) Source {
	return &multiSource{children: children}
}
