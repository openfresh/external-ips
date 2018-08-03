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
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/setting"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// The annotation used for figuring out which controller is responsible
	controllerAnnotationKey = "external-ips.alpha.openfresh.github.io/controller"
	// The annotation used for defining the desired hostname
	hostnameAnnotationKey = "external-ips.alpha.openfresh.github.io/hostname"
	// The annotation used for defining the desired selector
	selectorAnnotationKey = "external-ips.alpha.openfresh.github.io/selector"
	// The annotation used for defining the desired maxips
	maxipsAnnotationKey = "external-ips.alpha.openfresh.github.io/maxips"
	// The annotation used for defining the desired DNS record TTL
	ttlAnnotationKey = "external-ips.alpha.openfresh.github.io/ttl"
	// The value of the controller annotation so that we feel responsible
	controllerAnnotationValue = "dns-controller"
)

const (
	ttlMinimum = 1
	ttlMaximum = math.MaxUint32
)

type NodeIPs struct {
	externalIPs []string
	internalIPs []string
}

// Source defines the interface Endpoint sources should implement.
type Source interface {
	ExternalIPSetting() (*setting.ExternalIPSetting, error)
}

func getTTLFromAnnotations(annotations map[string]string) (endpoint.TTL, error) {
	ttlNotConfigured := endpoint.TTL(0)
	ttlAnnotation, exists := annotations[ttlAnnotationKey]
	if !exists {
		return ttlNotConfigured, nil
	}
	ttlValue, err := strconv.ParseInt(ttlAnnotation, 10, 64)
	if err != nil {
		return ttlNotConfigured, fmt.Errorf("\"%v\" is not a valid TTL value", ttlAnnotation)
	}
	if ttlValue < ttlMinimum || ttlValue > ttlMaximum {
		return ttlNotConfigured, fmt.Errorf("TTL value must be between [%d, %d]", ttlMinimum, ttlMaximum)
	}
	return endpoint.TTL(ttlValue), nil
}

func getHostnamesFromAnnotations(annotations map[string]string) []string {
	hostnameAnnotation, exists := annotations[hostnameAnnotationKey]
	if !exists {
		return nil
	}

	return strings.Split(strings.Replace(hostnameAnnotation, " ", "", -1), ",")
}

func getSelectorFromAnnotations(annotations map[string]string) (labels.Selector, error) {
	selectorAnnotation, exists := annotations[selectorAnnotationKey]
	if !exists {
		return nil, nil
	}

	labelSelector, err := metav1.ParseToLabelSelector(selectorAnnotation)
	if err != nil {
		return nil, err
	}
	return metav1.LabelSelectorAsSelector(labelSelector)
}

func getMaxIPsFromAnnotations(annotations map[string]string) (int, error) {
	maxipsAnnotation, exists := annotations[maxipsAnnotationKey]
	if !exists {
		return 0, nil
	}
	maxips, err := strconv.ParseInt(maxipsAnnotation, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("\"%v\" is not a valid Max IPs value", maxipsAnnotation)
	}
	return int(maxips), nil
}

// suitableType returns the DNS resource record type suitable for the target.
// In this case type A for IPs and type CNAME for everything else.
func suitableType(target string) string {
	if net.ParseIP(target) != nil {
		return endpoint.RecordTypeA
	}
	return endpoint.RecordTypeCNAME
}

func equalIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
