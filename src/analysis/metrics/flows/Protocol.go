package flows

import (
	"net"
	"test.com/scale/src/analysis/flows"
)

type MetricProtocol struct{}

func newMetricProtocol() *MetricProtocol {
	return &MetricProtocol{}
}

func (mp *MetricProtocol) onFlush(flow *flows.Flow) ExportableValue {
	/*
		TCPOptionsinFlow := false
		if flow.TCPOptionsinFlow != nil {
			TCPOptionsinFlow = true
		}
		TCPOptionsSever := false
		if flow.TCPOptionsSever != nil {
			TCPOptionsSever = true
		}
		TCPOptionsClient := false
		if flow.TCPOptionsClient != nil {
			TCPOptionsClient = true
		}*/

	value := ValueProtocol{
		protocol:      flows.GetProtocolString(flow.Protocol),
		portClient:    flow.ClientPort,
		portServer:    flow.ServerPort,
		addressClient: int64(flow.ClientAddr),
		addressServer: int64(flow.ServerAddr),
		//TCPOptionsSever:  fmt.Sprintf("%v", flow.TCPOptionsSever),
		//TCPOptionsClient: fmt.Sprintf("%v", flow.TCPOptionsClient),
		//TCPOptionsinFlow: fmt.Sprintf("%v", flow.TCPOptionsinFlow),
		//TCPOptionsinFlow: TCPOptionsinFlow,
		//TCPOptionsSever:  TCPOptionsSever,
		//TCPOptionsClient: TCPOptionsClient,
		//TCPOptionsinFlow:    flow.TCPOptionsinFlow,
		//TCPOptionsSever:     flow.TCPOptionsSever,
		//TCPOptionsClient:    flow.TCPOptionsClient,
		NewTCPOptionsServer: flow.NewTCPOptionsServer,
		NewTCPOptionsClient: flow.NewTCPOptionsClient,
		NewTCPOptionsinFlow: flow.NewTCPOptionsinFlow,
		ClientInterface:     flow.ClientInterface,
		ServerInterface:     flow.ServerInterface,
		ServerClientUnclear: flow.ServerClientUnclear,
	}

	return value
}

type ValueProtocol struct {
	// The name of the layer 4 protocol used.
	protocol string
	// Port number the client used.
	portClient uint16
	// Port number the server used.
	portServer uint16
	// Address the client used. Conversion to int64 needed for elasticsearch.
	addressClient int64
	// Address the server used. Conversion to int64 needed for elasticsearch.
	addressServer int64
	//tcp options
	//TCPOptionsSever     []layers.TCPOption
	//TCPOptionsClient    []layers.TCPOption
	//TCPOptionsinFlow    [][]layers.TCPOption

	NewTCPOptionsClient []flows.CustomTCPOption
	NewTCPOptionsServer []flows.CustomTCPOption
	NewTCPOptionsinFlow [][]flows.CustomTCPOption

	ClientInterface     net.HardwareAddr
	ServerInterface     net.HardwareAddr
	ServerClientUnclear bool

	//TCPOptionsinFlow string
	//TCPOptionsSever  string
	//TCPOptionsClient string
}

func (vp ValueProtocol) export() map[string]interface{} {
	return map[string]interface{}{
		"protocol":      vp.protocol,
		"portClient":    vp.portClient,
		"portServer":    vp.portServer,
		"addressClient": vp.addressClient,
		"addressServer": vp.addressServer,
		//"tcpOptionsServer":    vp.TCPOptionsSever,
		//"tcpOptionsClient":    vp.TCPOptionsClient,
		//"TCPOptionsinFlow":    vp.TCPOptionsinFlow,
		"ClientInterface":     vp.ClientInterface,
		"ServerInterface":     vp.ServerInterface,
		"ServerClientUnclear": vp.ServerClientUnclear,
		"NewTCPOptionsClient": vp.NewTCPOptionsClient,
		"NewTCPOptionsServer": vp.NewTCPOptionsServer,
		"NewTCPOptionsinFlow": vp.NewTCPOptionsinFlow,
	}
}
