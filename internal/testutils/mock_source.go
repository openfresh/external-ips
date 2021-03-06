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

package testutils

import (
	"github.com/stretchr/testify/mock"

	"github.com/openfresh/external-ips/setting"
)

// MockSource returns mock endpoints.
type MockSource struct {
	mock.Mock
}

// Endpoints returns the desired mock endpoints.
func (m *MockSource) ExternalIPSetting() (*setting.ExternalIPSetting, error) {
	args := m.Called()

	exipsetting := args.Get(0)
	if exipsetting == nil {
		return nil, args.Error(1)
	}

	return exipsetting.(*setting.ExternalIPSetting), args.Error(1)
}
