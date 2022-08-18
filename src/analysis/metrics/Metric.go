package metrics

import (
	"test.com/scale/src/analysis/flows"
)

type Metric interface {
	OnTCPFlush(flow *flows.TCPFlow)
	OnUDPFlush(flow *flows.UDPFlow)
}
