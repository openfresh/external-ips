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
	"github.com/openfresh/external-ips/extip/extip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/setting"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ServiceSuite struct {
	suite.Suite
	sc             Source
	fooWithTargets *v1.Service
}

func (suite *ServiceSuite) SetupTest() {
	fakeClient := fake.NewSimpleClientset()
	var err error

	suite.sc, err = NewServiceSource(
		fakeClient,
		"",
		"",
		"",
		"{{.Name}}",
		false,
		"",
		false,
		false,
	)
	suite.fooWithTargets = &v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "foo-with-targets",
			Annotations: map[string]string{},
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{IP: "8.8.8.8"},
					{Hostname: "foo"},
				},
			},
		},
	}

	suite.NoError(err, "should initialize service source")

	_, err = fakeClient.CoreV1().Services(suite.fooWithTargets.Namespace).Create(suite.fooWithTargets)
	suite.NoError(err, "should successfully create service")

}

func (suite *ServiceSuite) TestResourceLabelIsSet() {
	extipsetting, _ := suite.sc.ExternalIPSetting()
	for _, ep := range extipsetting.Endpoints {
		suite.Equal("service/default/foo-with-targets", ep.Labels[endpoint.ResourceLabelKey], "should set correct resource label")
	}
}

type NodeInfo struct {
	name       string
	providerID string
	internalIP string
	externalIP string
	labels     map[string]string
}

type PortInfo struct {
	protocol string
	port     int
}

func TestServiceSource(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
	t.Run("Interface", testServiceSourceImplementsSource)
	t.Run("NewServiceSource", testServiceSourceNewServiceSource)
	t.Run("Endpoints", testServiceSourceEndpoints)
}

// testServiceSourceImplementsSource tests that serviceSource is a valid Source.
func testServiceSourceImplementsSource(t *testing.T) {
	assert.Implements(t, (*Source)(nil), new(serviceSource))
}

// testServiceSourceNewServiceSource tests that NewServiceSource doesn't return an error.
func testServiceSourceNewServiceSource(t *testing.T) {
	for _, ti := range []struct {
		title            string
		annotationFilter string
		fqdnTemplate     string
		expectError      bool
	}{
		{
			title:        "invalid template",
			expectError:  true,
			fqdnTemplate: "{{.Name",
		},
		{
			title:       "valid empty template",
			expectError: false,
		},
		{
			title:        "valid template",
			expectError:  false,
			fqdnTemplate: "{{.Name}}-{{.Namespace}}.ext-dns.test.com",
		},
		{
			title:            "non-empty annotation filter label",
			expectError:      false,
			annotationFilter: "kubernetes.io/ingress.class=nginx",
		},
	} {
		t.Run(ti.title, func(t *testing.T) {
			_, err := NewServiceSource(
				fake.NewSimpleClientset(),
				"",
				"",
				ti.annotationFilter,
				ti.fqdnTemplate,
				false,
				"",
				false,
				false,
			)

			if ti.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// testServiceSourceEndpoints tests that various services generate the correct endpoints.
func testServiceSourceEndpoints(t *testing.T) {
	for _, tc := range []struct {
		title                    string
		clusterName              string
		targetNamespace          string
		annotationFilter         string
		svcNamespace             string
		svcName                  string
		svcType                  v1.ServiceType
		compatibility            string
		fqdnTemplate             string
		combineFQDNAndAnnotation bool
		labels                   map[string]string
		annotations              map[string]string
		clusterIP                string
		ports                    []PortInfo
		nodes                    []NodeInfo
		expected                 setting.ExternalIPSetting
		expectError              bool
	}{
		{
			"no annotated services return no setting",
			"",
			"",
			"",
			"testing",
			"foo",
			v1.ServiceTypeClusterIP,
			"",
			"",
			false,
			map[string]string{},
			map[string]string{},
			"",
			[]PortInfo{},
			[]NodeInfo{},
			setting.ExternalIPSetting{},
			false,
		},
		{
			"annotated services return an setting with external IP",
			"cl.kube.io",
			"",
			"",
			"testing",
			"foo",
			v1.ServiceTypeClusterIP,
			"",
			"",
			false,
			map[string]string{},
			map[string]string{
				hostnameAnnotationKey: "foo.example.org.",
			},
			"",
			[]PortInfo{
				{protocol: "udp", port: 5000},
			},
			[]NodeInfo{
				{
					name:       "node1",
					providerID: "abc",
					internalIP: "1.2.3.4",
					externalIP: "10.9.8.7",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
			},
			setting.ExternalIPSetting{
				Endpoints: []*endpoint.Endpoint{
					{DNSName: "foo.example.org", Targets: endpoint.Targets{"10.9.8.7"}},
				},
				InboundRules: []*inbound.InboundRules{
					{
						Name: "foo.testing.cl.kube.io",
						Rules: []inbound.InboundRule{
							{Protocol: "udp", Port: 5000},
						},
						ProviderIDs: inbound.ProviderIDs{"abc"},
					},
				},
				ExtIPs: []*extip.ExtIP{
					{SvcName: "foo", ExtIPs: endpoint.Targets{"1.2.3.4"}},
				},
			},
			false,
		},
		{
			"annotated services return an setting with 2 external IPs",
			"cl.kube.io",
			"",
			"",
			"testing",
			"foo",
			v1.ServiceTypeClusterIP,
			"",
			"",
			false,
			map[string]string{},
			map[string]string{
				hostnameAnnotationKey: "foo.example.org.",
				selectorAnnotationKey: "kops.k8s.io/instancegroup=general",
				maxipsAnnotationKey:   "2",
			},
			"",
			[]PortInfo{
				{protocol: "udp", port: 5000},
				{protocol: "tcp", port: 80},
				{protocol: "tcp", port: 443},
			},
			[]NodeInfo{
				{
					name:       "node1",
					providerID: "abc",
					internalIP: "1.2.3.4",
					externalIP: "10.9.8.7",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
				{
					name:       "node2",
					providerID: "def",
					internalIP: "1.2.3.5",
					externalIP: "10.9.8.6",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
				{
					name:       "node3",
					providerID: "ghi",
					internalIP: "1.2.3.6",
					externalIP: "10.9.8.5",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
			},
			setting.ExternalIPSetting{
				Endpoints: []*endpoint.Endpoint{
					{DNSName: "foo.example.org", Targets: endpoint.Targets{"10.9.8.7", "10.9.8.6"}},
				},
				InboundRules: []*inbound.InboundRules{
					{
						Name: "foo.testing.cl.kube.io",
						Rules: []inbound.InboundRule{
							{Protocol: "udp", Port: 5000},
							{Protocol: "tcp", Port: 80},
							{Protocol: "tcp", Port: 443},
						},
						ProviderIDs: inbound.ProviderIDs{"abc", "def"},
					},
				},
				ExtIPs: []*extip.ExtIP{
					{SvcName: "foo", ExtIPs: endpoint.Targets{"1.2.3.4", "1.2.3.5"}},
				},
			},
			false,
		},
		{
			"annotated services return an setting with 1 external IP",
			"cl.kube.io",
			"",
			"",
			"testing",
			"foo",
			v1.ServiceTypeClusterIP,
			"",
			"",
			false,
			map[string]string{},
			map[string]string{
				hostnameAnnotationKey: "foo.example.org.",
				selectorAnnotationKey: "kops.k8s.io/instancegroup=special",
				maxipsAnnotationKey:   "2",
			},
			"",
			[]PortInfo{
				{protocol: "udp", port: 5000},
			},
			[]NodeInfo{
				{
					name:       "node1",
					providerID: "abc",
					internalIP: "1.2.3.4",
					externalIP: "10.9.8.7",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
				{
					name:       "node2",
					providerID: "def",
					internalIP: "1.2.3.5",
					externalIP: "10.9.8.6",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "general",
					},
				},
				{
					name:       "node3",
					providerID: "ghi",
					internalIP: "1.2.3.6",
					externalIP: "10.9.8.5",
					labels: map[string]string{
						"kops.k8s.io/instancegroup": "special",
					},
				},
			},
			setting.ExternalIPSetting{
				Endpoints: []*endpoint.Endpoint{
					{DNSName: "foo.example.org", Targets: endpoint.Targets{"10.9.8.5"}},
				},
				InboundRules: []*inbound.InboundRules{
					{
						Name: "foo.testing.cl.kube.io",
						Rules: []inbound.InboundRule{
							{Protocol: "udp", Port: 5000},
						},
						ProviderIDs: inbound.ProviderIDs{"ghi"},
					},
				},
				ExtIPs: []*extip.ExtIP{
					{SvcName: "foo", ExtIPs: endpoint.Targets{"1.2.3.6"}},
				},
			},
			false,
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			// Create a Kubernetes testing client
			kubernetes := fake.NewSimpleClientset()

			ports := []v1.ServicePort{}
			for _, port := range tc.ports {
				ports = append(ports, v1.ServicePort{
					Protocol: v1.Protocol(port.protocol),
					Port:     int32(port.port),
				})
			}

			service := &v1.Service{
				Spec: v1.ServiceSpec{
					Type:      tc.svcType,
					ClusterIP: tc.clusterIP,
					Ports:     ports,
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   tc.svcNamespace,
					Name:        tc.svcName,
					Labels:      tc.labels,
					Annotations: tc.annotations,
				},
			}

			_, err := kubernetes.CoreV1().Services(service.Namespace).Create(service)
			require.NoError(t, err)

			// Create our object under test and get the endpoints.
			client, _ := NewServiceSource(
				kubernetes,
				tc.clusterName,
				tc.targetNamespace,
				tc.annotationFilter,
				tc.fqdnTemplate,
				tc.combineFQDNAndAnnotation,
				tc.compatibility,
				false,
				false,
			)
			require.NoError(t, err)

			for _, nodeInfo := range tc.nodes {
				node := &v1.Node{
					Spec: v1.NodeSpec{
						ProviderID: nodeInfo.providerID,
					},
					Status: v1.NodeStatus{
						Addresses: []v1.NodeAddress{
							{Type: v1.NodeExternalIP, Address: nodeInfo.externalIP},
							{Type: v1.NodeInternalIP, Address: nodeInfo.internalIP},
						},
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:   nodeInfo.name,
						Labels: nodeInfo.labels,
					},
				}
				_, err := kubernetes.CoreV1().Nodes().Create(node)
				require.NoError(t, err)
			}

			extipsetting, err := client.ExternalIPSetting()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Validate returned setting against desired setting.
			validateSetting(t, extipsetting, &tc.expected)
		})
	}
}
