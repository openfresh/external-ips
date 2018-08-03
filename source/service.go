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
	"fmt"
	"sort"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/setting"
)

const (
	defaultTargetsCapacity = 10
)

// serviceSource is an implementation of Source for Kubernetes service objects.
// It will find all services that are under our jurisdiction, i.e. annotated
// desired hostname and matching or no controller annotation. For each of the
// matched services' entrypoints it will return a corresponding
// Endpoint object.
type serviceSource struct {
	client           kubernetes.Interface
	clusterName      string
	namespace        string
	annotationFilter string
	// process Services with legacy annotations
	compatibility         string
	fqdnTemplate          *template.Template
	combineFQDNAnnotation bool
	publishInternal       bool
	dryRun                bool
}

// NewServiceSource creates a new serviceSource with the given config.
func NewServiceSource(kubeClient kubernetes.Interface, clusterName, namespace, annotationFilter string, fqdnTemplate string, combineFqdnAnnotation bool, compatibility string, publishInternal bool, dryRun bool) (Source, error) {
	var (
		tmpl *template.Template
		err  error
	)
	if fqdnTemplate != "" {
		tmpl, err = template.New("endpoint").Funcs(template.FuncMap{
			"trimPrefix": strings.TrimPrefix,
		}).Parse(fqdnTemplate)
		if err != nil {
			return nil, err
		}
	}

	return &serviceSource{
		client:                kubeClient,
		clusterName:           clusterName,
		namespace:             namespace,
		annotationFilter:      annotationFilter,
		compatibility:         compatibility,
		fqdnTemplate:          tmpl,
		combineFQDNAnnotation: combineFqdnAnnotation,
		publishInternal:       publishInternal,
		dryRun:                dryRun,
	}, nil
}

// Endpoints returns endpoint objects for each service that should be processed.
func (sc *serviceSource) ExternalIPSetting() (*setting.ExternalIPSetting, error) {
	services, err := sc.client.CoreV1().Services(sc.namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	services.Items, err = sc.filterByAnnotations(services.Items)
	if err != nil {
		return nil, err
	}

	// get all the nodes and cache them for this run
	nodes, err := sc.extractNodes()
	if err != nil {
		return nil, err
	}

	// The result of next run will be same by sorting by creation time unless node is removed
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].CreationTimestamp.Before(nodes[j].CreationTimestamp)
	})

	setting := setting.ExternalIPSetting{
		Endpoints:    []*endpoint.Endpoint{},
		InboundRules: []*inbound.InboundRules{},
	}

	for _, svc := range services.Items {
		hostnameList := getHostnamesFromAnnotations(svc.Annotations)
		if len(hostnameList) == 0 {
			continue
		}

		externalIPs, internalIPs, providerIDs, err := sc.extractNodeInfo(&svc, nodes)
		if err != nil {
			return nil, err
		}

		err = sc.updateExternalIPs(&svc, internalIPs)
		if err != nil {
			return nil, err
		}

		svcEndpoints := sc.endpoints(&svc, externalIPs)

		inboundRules := sc.inboundRules(&svc, providerIDs, sc.clusterName)

		log.Debugf("External IPs setting generated from service: %s/%s: %v", svc.Namespace, svc.Name, setting)
		sc.setResourceLabel(svc, setting.Endpoints)
		setting.Endpoints = append(setting.Endpoints, svcEndpoints...)
		setting.InboundRules = append(setting.InboundRules, inboundRules)
	}

	return &setting, nil
}

func (sc *serviceSource) extractNodeInfo(svc *v1.Service, nodes []v1.Node) (endpoint.Targets, endpoint.Targets, []string, error) {
	selector, err := getSelectorFromAnnotations(svc.Annotations)
	if err != nil {
		return nil, nil, nil, err
	}
	maxips, err := getMaxIPsFromAnnotations(svc.Annotations)
	if err != nil {
		return nil, nil, nil, err
	}

	var externalIPs endpoint.Targets
	var internalIPs endpoint.Targets
	var providerIDs []string
	selectedNode := 0

	for _, node := range nodes {
		labels := labels.Set(node.Labels)

		if selector == nil || selector.Matches(labels) {
			for _, address := range node.Status.Addresses {
				switch address.Type {
				case v1.NodeExternalIP:
					externalIPs = append(externalIPs, address.Address)
				case v1.NodeInternalIP:
					internalIPs = append(internalIPs, address.Address)
				}
			}
			providerIDs = append(providerIDs, node.Spec.ProviderID)
			selectedNode++
		}
		if maxips > 0 && selectedNode >= maxips {
			break
		}
	}
	sort.Sort(externalIPs)
	sort.Sort(internalIPs)
	return externalIPs, internalIPs, providerIDs, nil
}

func (sc *serviceSource) updateExternalIPs(svc *v1.Service, internalIPs []string) error {
	if !equalIPs(svc.Spec.ExternalIPs, internalIPs) {
		log.Infof("Desired change: %s %s %s", "UPDATE ExternalIPs", svc.Name, strings.Join(internalIPs, ";"))
		if !sc.dryRun {
			svc.Spec.ExternalIPs = internalIPs
			newsvc, err := sc.client.CoreV1().Services(svc.Namespace).Update(svc)
			if err != nil {
				return err
			}
			log.Debugf("external IPs was updated at service: %s/%s", newsvc.Namespace, newsvc.Name)
		}
	}
	return nil
}

// endpointsFromService extracts the endpoints from a service object
func (sc *serviceSource) endpoints(svc *v1.Service, nodeTargets endpoint.Targets) []*endpoint.Endpoint {
	var endpoints []*endpoint.Endpoint

	hostnameList := getHostnamesFromAnnotations(svc.Annotations)
	for _, hostname := range hostnameList {
		endpoints = append(endpoints, sc.generateEndpoint(svc, hostname, nodeTargets))
	}

	return endpoints
}

func (sc *serviceSource) inboundRules(svc *v1.Service, providerIDs []string, clusterName string) *inbound.InboundRules {
	inboundRules := inbound.NewInboundRules()
	inboundRules.ProviderIDs = providerIDs
	for _, port := range svc.Spec.Ports {
		// figure out the protocol
		protocol := strings.ToLower(string(port.Protocol))
		if protocol == "" {
			protocol = "tcp"
		}

		rule := inbound.InboundRule{
			Protocol: protocol,
			Port:     int(port.Port),
		}
		inboundRules.Rules = append(inboundRules.Rules, rule)
	}
	inboundRules.Name = svc.Name
	if svc.Namespace != "default" && len(svc.Namespace) > 0 {
		inboundRules.Name += "." + svc.Namespace
	}
	inboundRules.Name += "." + clusterName
	return inboundRules
}

// filterByAnnotations filters a list of services by a given annotation selector.
func (sc *serviceSource) filterByAnnotations(services []v1.Service) ([]v1.Service, error) {
	labelSelector, err := metav1.ParseToLabelSelector(sc.annotationFilter)
	if err != nil {
		return nil, err
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return nil, err
	}

	// empty filter returns original list
	if selector.Empty() {
		return services, nil
	}

	filteredList := []v1.Service{}

	for _, service := range services {
		// convert the service's annotations to an equivalent label selector
		annotations := labels.Set(service.Annotations)

		// include service if its annotations match the selector
		if selector.Matches(annotations) {
			filteredList = append(filteredList, service)
		}
	}

	return filteredList, nil
}

func (sc *serviceSource) extractNodes() ([]v1.Node, error) {
	nodes, err := sc.client.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return nodes.Items, nil
}

func (sc *serviceSource) setResourceLabel(service v1.Service, endpoints []*endpoint.Endpoint) {
	for _, ep := range endpoints {
		ep.Labels[endpoint.ResourceLabelKey] = fmt.Sprintf("service/%s/%s", service.Namespace, service.Name)
	}
}

func (sc *serviceSource) generateEndpoint(svc *v1.Service, hostname string, nodeTargets endpoint.Targets) *endpoint.Endpoint {
	hostname = strings.TrimSuffix(hostname, ".")
	ttl, err := getTTLFromAnnotations(svc.Annotations)
	if err != nil {
		log.Warn(err)
	}

	ep := &endpoint.Endpoint{
		RecordTTL:  ttl,
		RecordType: endpoint.RecordTypeA,
		Labels:     endpoint.NewLabels(),
		Targets:    make(endpoint.Targets, 0, defaultTargetsCapacity),
		DNSName:    hostname,
	}

	for _, t := range nodeTargets {
		ep.Targets = append(ep.Targets, t)
	}

	return ep
}
