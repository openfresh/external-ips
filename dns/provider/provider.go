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
	"net"
	"strings"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/dns/plan"
)

// Provider defines the interface DNS providers should implement.
type Provider interface {
	Records() ([]*endpoint.Endpoint, error)
	ApplyChanges(changes *plan.Changes) error
}

// ensureTrailingDot ensures that the hostname receives a trailing dot if it hasn't already.
func ensureTrailingDot(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}

	return strings.TrimSuffix(hostname, ".") + "."
}
