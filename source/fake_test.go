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
	"net"
	"regexp"
	"testing"

	"github.com/openfresh/external-ips/setting"
)

func generateTestSetting() *setting.ExternalIPSetting {
	sc, _ := NewFakeSource("")

	setting, _ := sc.ExternalIPSetting()

	return setting
}

func TestFakeSourceReturnsTenSetting(t *testing.T) {
	setting := generateTestSetting()

	count := len(setting.Endpoints)

	if count != 10 {
		t.Error(count)
	}
}

func TestFakeEndpointsBelongToDomain(t *testing.T) {
	validRecord := regexp.MustCompile(`^[a-z]{4}\.example\.com$`)

	setting := generateTestSetting()

	for _, e := range setting.Endpoints {
		valid := validRecord.MatchString(e.DNSName)

		if !valid {
			t.Error(e.DNSName)
		}
	}
}

func TestFakeSettingsResolveToIPAddresses(t *testing.T) {
	setting := generateTestSetting()

	for _, e := range setting.Endpoints {
		ip := net.ParseIP(e.Targets[0])

		if ip == nil {
			t.Error(e)
		}
	}
}

// Validate that FakeSource is a source
var _ Source = &fakeSource{}
