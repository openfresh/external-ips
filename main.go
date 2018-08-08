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

package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/openfresh/external-ips/controller"
	"github.com/openfresh/external-ips/dns/plan"
	"github.com/openfresh/external-ips/dns/provider"
	"github.com/openfresh/external-ips/dns/registry"
	eipprovider "github.com/openfresh/external-ips/extip/provider"
	eipregistry "github.com/openfresh/external-ips/extip/registry"
	fwprovider "github.com/openfresh/external-ips/firewall/provider"
	fwregistry "github.com/openfresh/external-ips/firewall/registry"
	"github.com/openfresh/external-ips/pkg/apis/externalips"
	"github.com/openfresh/external-ips/pkg/apis/externalips/validation"
	"github.com/openfresh/external-ips/source"
)

func main() {
	cfg := externalips.NewConfig()
	if err := cfg.ParseFlags(os.Args[1:]); err != nil {
		log.Fatalf("flag parsing error: %v", err)
	}
	log.Infof("config: %s", cfg)

	if err := validation.ValidateConfig(cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}

	if cfg.LogFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.DryRun {
		log.Info("running in dry-run mode. No changes to DNS records will be made.")
	}

	ll, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to parse log level: %v", err)
	}
	log.SetLevel(ll)

	stopChan := make(chan struct{}, 1)

	go serveMetrics(cfg.MetricsAddress)
	go handleSigterm(stopChan)

	// Create a source.Config from the flags passed by the user.
	sourceCfg := &source.Config{
		Namespace:                cfg.Namespace,
		AnnotationFilter:         cfg.AnnotationFilter,
		FQDNTemplate:             cfg.FQDNTemplate,
		CombineFQDNAndAnnotation: cfg.CombineFQDNAndAnnotation,
		Compatibility:            cfg.Compatibility,
		PublishInternal:          cfg.PublishInternal,
		DryRun:                   cfg.DryRun,
	}

	clientGenerator := source.SingletonClientGenerator{
		KubeConfig: cfg.KubeConfig,
		KubeMaster: cfg.Master,
	}
	kubeClient, err := clientGenerator.KubeClient()
	if err != nil {
		log.Fatal(err)
	}

	var fwp fwprovider.Provider
	switch cfg.Provider {
	case "aws":
		fwp, err = fwprovider.NewAWSProvider(
			fwprovider.AWSConfig{
				AssumeRole: cfg.AWSAssumeRole,
				DryRun:     cfg.DryRun,
			},
			kubeClient,
		)
	case "aws-sd":
		fwp, err = fwprovider.NewAWSProvider(
			fwprovider.AWSConfig{
				AssumeRole: cfg.AWSAssumeRole,
				DryRun:     cfg.DryRun,
			},
			kubeClient,
		)
	default:
		log.Fatalf("unknown firewall provider: %s", cfg.Provider)
	}
	if err != nil {
		log.Fatal(err)
	}

	clusterName, err := fwp.GetClusterName()
	if err != nil {
		log.Fatal(err)
	}

	// Lookup all the selected sources by names and pass them the desired configuration.
	sources, err := source.ByNames(&clientGenerator, cfg.Sources, sourceCfg, clusterName)
	if err != nil {
		log.Fatal(err)
	}

	// Combine multiple sources into a single.
	endpointsSource := source.NewMultiSource(sources)

	domainFilter := provider.NewDomainFilter(cfg.DomainFilter)
	zoneIDFilter := provider.NewZoneIDFilter(cfg.ZoneIDFilter)
	zoneTypeFilter := provider.NewZoneTypeFilter(cfg.AWSZoneType)

	var p provider.Provider
	switch cfg.Provider {
	case "aws":
		p, err = provider.NewAWSProvider(
			provider.AWSConfig{
				DomainFilter:   domainFilter,
				ZoneIDFilter:   zoneIDFilter,
				ZoneTypeFilter: zoneTypeFilter,
				MaxChangeCount: cfg.AWSMaxChangeCount,
				AssumeRole:     cfg.AWSAssumeRole,
				DryRun:         cfg.DryRun,
			},
		)
	case "aws-sd":
		// Check that only compatible Registry is used with AWS-SD
		if cfg.Registry != "noop" && cfg.Registry != "aws-sd" {
			log.Infof("Registry \"%s\" cannot be used with AWS ServiceDiscovery. Switching to \"aws-sd\".", cfg.Registry)
			cfg.Registry = "aws-sd"
		}
		p, err = provider.NewAWSSDProvider(domainFilter, cfg.AWSZoneType, cfg.DryRun)
	default:
		log.Fatalf("unknown dns provider: %s", cfg.Provider)
	}
	if err != nil {
		log.Fatal(err)
	}

	eipp, err := eipprovider.NewProvider(kubeClient, cfg.Namespace, cfg.DryRun)
	if err != nil {
		log.Fatal(err)
	}

	var r registry.Registry
	switch cfg.Registry {
	case "noop":
		r, err = registry.NewNoopRegistry(p)
	case "txt":
		r, err = registry.NewTXTRegistry(p, cfg.TXTPrefix, cfg.TXTOwnerID, cfg.TXTCacheInterval)
	case "aws-sd":
		r, err = registry.NewAWSSDRegistry(p.(*provider.AWSSDProvider), cfg.TXTOwnerID)
	default:
		log.Fatalf("unknown registry: %s", cfg.Registry)
	}

	if err != nil {
		log.Fatal(err)
	}

	policy, exists := plan.Policies[cfg.Policy]
	if !exists {
		log.Fatalf("unknown policy: %s", cfg.Policy)
	}

	fwr, err := fwregistry.NewRegistry(fwp)
	if err != nil {
		log.Fatal(err)
	}

	eipr, err := eipregistry.NewRegistry(eipp)
	if err != nil {
		log.Fatal(err)
	}

	ctrl := controller.Controller{
		Source:      endpointsSource,
		Registry:    r,
		FwRegistry:  fwr,
		EipRegistry: eipr,
		Policy:      policy,
		Interval:    cfg.Interval,
	}

	if cfg.Once {
		err := ctrl.RunOnce()
		if err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}
	ctrl.Run(stopChan)
}

func handleSigterm(stopChan chan struct{}) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	<-signals
	log.Info("Received SIGTERM. Terminating...")
	close(stopChan)
}

func serveMetrics(address string) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(address, nil))
}
