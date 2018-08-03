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

package externalips

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	minimalConfig = &Config{
		Master:                  "",
		KubeConfig:              "",
		Sources:                 []string{"service"},
		Namespace:               "",
		FQDNTemplate:            "",
		Compatibility:           "",
		Provider:                "google",
		GoogleProject:           "",
		DomainFilter:            []string{""},
		ZoneIDFilter:            []string{""},
		AWSZoneType:             "",
		AWSAssumeRole:           "",
		AWSMaxChangeCount:       4000,
		AWSEvaluateTargetHealth: true,
		AzureConfigFile:         "/etc/kubernetes/azure.json",
		AzureResourceGroup:      "",
		CloudflareProxied:       false,
		InfobloxGridHost:        "",
		InfobloxWapiPort:        443,
		InfobloxWapiUsername:    "admin",
		InfobloxWapiPassword:    "",
		InfobloxWapiVersion:     "2.3.1",
		InfobloxSSLVerify:       true,
		OCIConfigFile:           "/etc/kubernetes/oci.yaml",
		InMemoryZones:           []string{""},
		PDNSServer:              "http://localhost:8081",
		PDNSAPIKey:              "",
		Policy:                  "sync",
		Registry:                "txt",
		TXTOwnerID:              "default",
		TXTPrefix:               "",
		TXTCacheInterval:        0,
		Interval:                time.Minute,
		Once:                    false,
		DryRun:                  false,
		LogFormat:               "text",
		MetricsAddress:          ":7979",
		LogLevel:                logrus.InfoLevel.String(),
		ExoscaleEndpoint:        "https://api.exoscale.ch/dns",
		ExoscaleAPIKey:          "",
		ExoscaleAPISecret:       "",
	}

	overriddenConfig = &Config{
		Master:                  "http://127.0.0.1:8080",
		KubeConfig:              "/some/path",
		Sources:                 []string{"service"},
		Namespace:               "namespace",
		FQDNTemplate:            "{{.Name}}.service.example.com",
		Compatibility:           "mate",
		Provider:                "google",
		GoogleProject:           "project",
		DomainFilter:            []string{"example.org", "company.com"},
		ZoneIDFilter:            []string{"/hostedzone/ZTST1", "/hostedzone/ZTST2"},
		AWSZoneType:             "private",
		AWSAssumeRole:           "some-other-role",
		AWSMaxChangeCount:       100,
		AWSEvaluateTargetHealth: false,
		AzureConfigFile:         "azure.json",
		AzureResourceGroup:      "arg",
		CloudflareProxied:       true,
		InfobloxGridHost:        "127.0.0.1",
		InfobloxWapiPort:        8443,
		InfobloxWapiUsername:    "infoblox",
		InfobloxWapiPassword:    "infoblox",
		InfobloxWapiVersion:     "2.6.1",
		InfobloxSSLVerify:       false,
		OCIConfigFile:           "oci.yaml",
		InMemoryZones:           []string{"example.org", "company.com"},
		PDNSServer:              "http://ns.example.com:8081",
		PDNSAPIKey:              "some-secret-key",
		PDNSTLSEnabled:          true,
		TLSCA:                   "/path/to/ca.crt",
		TLSClientCert:           "/path/to/cert.pem",
		TLSClientCertKey:        "/path/to/key.pem",
		Policy:                  "upsert-only",
		Registry:                "noop",
		TXTOwnerID:              "owner-1",
		TXTPrefix:               "associated-txt-record",
		TXTCacheInterval:        12 * time.Hour,
		Interval:                10 * time.Minute,
		Once:                    true,
		DryRun:                  true,
		LogFormat:               "json",
		MetricsAddress:          "127.0.0.1:9099",
		LogLevel:                logrus.DebugLevel.String(),
		ExoscaleEndpoint:        "https://api.foo.ch/dns",
		ExoscaleAPIKey:          "1",
		ExoscaleAPISecret:       "2",
	}
)

func TestParseFlags(t *testing.T) {
	for _, ti := range []struct {
		title    string
		args     []string
		envVars  map[string]string
		expected *Config
	}{
		{
			title: "default config with minimal flags defined",
			args: []string{
				"--source=service",
				"--provider=google",
			},
			envVars:  map[string]string{},
			expected: minimalConfig,
		},
		{
			title: "override everything via flags",
			args: []string{
				"--master=http://127.0.0.1:8080",
				"--kubeconfig=/some/path",
				"--source=service",
				"--namespace=namespace",
				"--fqdn-template={{.Name}}.service.example.com",
				"--compatibility=mate",
				"--provider=google",
				"--google-project=project",
				"--azure-config-file=azure.json",
				"--azure-resource-group=arg",
				"--cloudflare-proxied",
				"--infoblox-grid-host=127.0.0.1",
				"--infoblox-wapi-port=8443",
				"--infoblox-wapi-username=infoblox",
				"--infoblox-wapi-password=infoblox",
				"--infoblox-wapi-version=2.6.1",
				"--inmemory-zone=example.org",
				"--inmemory-zone=company.com",
				"--pdns-server=http://ns.example.com:8081",
				"--pdns-api-key=some-secret-key",
				"--pdns-tls-enabled",
				"--oci-config-file=oci.yaml",
				"--tls-ca=/path/to/ca.crt",
				"--tls-client-cert=/path/to/cert.pem",
				"--tls-client-cert-key=/path/to/key.pem",
				"--no-infoblox-ssl-verify",
				"--domain-filter=example.org",
				"--domain-filter=company.com",
				"--zone-id-filter=/hostedzone/ZTST1",
				"--zone-id-filter=/hostedzone/ZTST2",
				"--aws-zone-type=private",
				"--aws-assume-role=some-other-role",
				"--aws-max-change-count=100",
				"--no-aws-evaluate-target-health",
				"--policy=upsert-only",
				"--registry=noop",
				"--txt-owner-id=owner-1",
				"--txt-prefix=associated-txt-record",
				"--txt-cache-interval=12h",
				"--interval=10m",
				"--once",
				"--dry-run",
				"--log-format=json",
				"--metrics-address=127.0.0.1:9099",
				"--log-level=debug",
				"--exoscale-endpoint=https://api.foo.ch/dns",
				"--exoscale-apikey=1",
				"--exoscale-apisecret=2",
			},
			envVars:  map[string]string{},
			expected: overriddenConfig,
		},
		{
			title: "override everything via environment variables",
			args:  []string{},
			envVars: map[string]string{
				"EXTERNAL_DNS_MASTER":                     "http://127.0.0.1:8080",
				"EXTERNAL_DNS_KUBECONFIG":                 "/some/path",
				"EXTERNAL_DNS_SOURCE":                     "service",
				"EXTERNAL_DNS_NAMESPACE":                  "namespace",
				"EXTERNAL_DNS_FQDN_TEMPLATE":              "{{.Name}}.service.example.com",
				"EXTERNAL_DNS_COMPATIBILITY":              "mate",
				"EXTERNAL_DNS_PROVIDER":                   "google",
				"EXTERNAL_DNS_GOOGLE_PROJECT":             "project",
				"EXTERNAL_DNS_AZURE_CONFIG_FILE":          "azure.json",
				"EXTERNAL_DNS_AZURE_RESOURCE_GROUP":       "arg",
				"EXTERNAL_DNS_CLOUDFLARE_PROXIED":         "1",
				"EXTERNAL_DNS_INFOBLOX_GRID_HOST":         "127.0.0.1",
				"EXTERNAL_DNS_INFOBLOX_WAPI_PORT":         "8443",
				"EXTERNAL_DNS_INFOBLOX_WAPI_USERNAME":     "infoblox",
				"EXTERNAL_DNS_INFOBLOX_WAPI_PASSWORD":     "infoblox",
				"EXTERNAL_DNS_INFOBLOX_WAPI_VERSION":      "2.6.1",
				"EXTERNAL_DNS_INFOBLOX_SSL_VERIFY":        "0",
				"EXTERNAL_DNS_OCI_CONFIG_FILE":            "oci.yaml",
				"EXTERNAL_DNS_INMEMORY_ZONE":              "example.org\ncompany.com",
				"EXTERNAL_DNS_DOMAIN_FILTER":              "example.org\ncompany.com",
				"EXTERNAL_DNS_PDNS_SERVER":                "http://ns.example.com:8081",
				"EXTERNAL_DNS_PDNS_API_KEY":               "some-secret-key",
				"EXTERNAL_DNS_PDNS_TLS_ENABLED":           "1",
				"EXTERNAL_DNS_TLS_CA":                     "/path/to/ca.crt",
				"EXTERNAL_DNS_TLS_CLIENT_CERT":            "/path/to/cert.pem",
				"EXTERNAL_DNS_TLS_CLIENT_CERT_KEY":        "/path/to/key.pem",
				"EXTERNAL_DNS_ZONE_ID_FILTER":             "/hostedzone/ZTST1\n/hostedzone/ZTST2",
				"EXTERNAL_DNS_AWS_ZONE_TYPE":              "private",
				"EXTERNAL_DNS_AWS_ASSUME_ROLE":            "some-other-role",
				"EXTERNAL_DNS_AWS_MAX_CHANGE_COUNT":       "100",
				"EXTERNAL_DNS_AWS_EVALUATE_TARGET_HEALTH": "0",
				"EXTERNAL_DNS_POLICY":                     "upsert-only",
				"EXTERNAL_DNS_REGISTRY":                   "noop",
				"EXTERNAL_DNS_TXT_OWNER_ID":               "owner-1",
				"EXTERNAL_DNS_TXT_PREFIX":                 "associated-txt-record",
				"EXTERNAL_DNS_TXT_CACHE_INTERVAL":         "12h",
				"EXTERNAL_DNS_INTERVAL":                   "10m",
				"EXTERNAL_DNS_ONCE":                       "1",
				"EXTERNAL_DNS_DRY_RUN":                    "1",
				"EXTERNAL_DNS_LOG_FORMAT":                 "json",
				"EXTERNAL_DNS_METRICS_ADDRESS":            "127.0.0.1:9099",
				"EXTERNAL_DNS_LOG_LEVEL":                  "debug",
				"EXTERNAL_DNS_EXOSCALE_ENDPOINT":          "https://api.foo.ch/dns",
				"EXTERNAL_DNS_EXOSCALE_APIKEY":            "1",
				"EXTERNAL_DNS_EXOSCALE_APISECRET":         "2",
			},
			expected: overriddenConfig,
		},
	} {
		t.Run(ti.title, func(t *testing.T) {
			originalEnv := setEnv(t, ti.envVars)
			defer func() { restoreEnv(t, originalEnv) }()

			cfg := NewConfig()
			require.NoError(t, cfg.ParseFlags(ti.args))
			assert.Equal(t, ti.expected, cfg)
		})
	}
}

// helper functions

func setEnv(t *testing.T, env map[string]string) map[string]string {
	originalEnv := map[string]string{}

	for k, v := range env {
		originalEnv[k] = os.Getenv(k)
		require.NoError(t, os.Setenv(k, v))
	}

	return originalEnv
}

func restoreEnv(t *testing.T, originalEnv map[string]string) {
	for k, v := range originalEnv {
		require.NoError(t, os.Setenv(k, v))
	}
}

func TestPasswordsNotLogged(t *testing.T) {
	cfg := Config{
		DynPassword:          "dyn-pass",
		InfobloxWapiPassword: "infoblox-pass",
		PDNSAPIKey:           "pdns-api-key",
	}

	s := cfg.String()

	assert.False(t, strings.Contains(s, "dyn-pass"))
	assert.False(t, strings.Contains(s, "infoblox-pass"))
	assert.False(t, strings.Contains(s, "pdns-api-key"))
}
