// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package extip

import (
	"github.com/openfresh/external-ips/dns/endpoint"
)

type ExtIP struct {
	SvcName string
	ExtIPs  endpoint.Targets
}

type BySvcName []*ExtIP

func (a BySvcName) Len() int           { return len(a) }
func (a BySvcName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a BySvcName) Less(i, j int) bool { return a[i].SvcName < a[j].SvcName }
