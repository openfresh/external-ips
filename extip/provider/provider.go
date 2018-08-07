// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package provider

import (
	"strings"

	"github.com/openfresh/external-ips/extip/extip"
	"github.com/openfresh/external-ips/extip/plan"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Provider defines the interface DNS providers should implement.
type Provider interface {
	ExtIPs() ([]*extip.ExtIP, error)
	ApplyChanges(changes *plan.Changes) error
}

type ProviderImpl struct {
	kubeClient kubernetes.Interface
	namespace  string
	dryRun     bool
}

func NewProvider(kubeClient kubernetes.Interface, namespace string, dryRun bool) (Provider, error) {
	return &ProviderImpl{
		kubeClient: kubeClient,
		namespace:  namespace,
		dryRun:     dryRun,
	}, nil
}

// ExtIPs returns the current extips from the cluster
func (im *ProviderImpl) ExtIPs() ([]*extip.ExtIP, error) {
	services, err := im.kubeClient.CoreV1().Services(im.namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	extips := make([]*extip.ExtIP, 0, len(services.Items))
	for _, svc := range services.Items {
		extip := extip.ExtIP{
			SvcName: svc.Name,
			ExtIPs:  svc.Spec.ExternalIPs,
		}
		extips = append(extips, &extip)
	}
	return extips, nil
}

// ApplyChanges propagates changes to the cluster
func (im *ProviderImpl) ApplyChanges(changes *plan.Changes) error {
	for _, e := range changes.UpdateNew {
		svc, err := im.kubeClient.CoreV1().Services(im.namespace).Get(e.SvcName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		svc.Spec.ExternalIPs = e.ExtIPs
		log.Infof("Desired change: %s %s %s", "UPDATE ExternalIPs", e.SvcName, strings.Join(e.ExtIPs, ";"))
		if !im.dryRun {
			newsvc, err := im.kubeClient.CoreV1().Services(im.namespace).Update(svc)
			if err != nil {
				return err
			}
			log.Debugf("external IPs was updated at service: %s/%s", newsvc.Namespace, newsvc.Name)
		}
	}
	return nil
}
