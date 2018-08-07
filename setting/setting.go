package setting

import (
	"github.com/openfresh/external-ips/dns/endpoint"
	"github.com/openfresh/external-ips/extip/extip"
	"github.com/openfresh/external-ips/firewall/inbound"
)

type ExternalIPSetting struct {
	Endpoints    []*endpoint.Endpoint
	InboundRules []*inbound.InboundRules
	ExtIPs       []*extip.ExtIP
}
