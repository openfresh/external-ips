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
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/firewall/plan"
)

// Provider defines the interface DNS providers should implement.
type Provider interface {
	Rules() ([]*inbound.InboundRules, error)
	ApplyChanges(changes *plan.Changes) error
}