package pool

// This file manages multiple pools, distributes data.

import (
	"fmt"
	"github.com/dustin/go-humanize"
	"sync"
	"test.com/scale/src/analysis/flows"
	"test.com/scale/src/analysis/metrics"
)

// NumFlowThreads defines the number of Threads (x2 (TCP & UDP)) which are responsible to add packets
const NumFlowThreads = 14

// AddPacketChannelSize defines the size of the channel
const AddPacketChannelSize = 300

// PacketInformationCacheSize is the batching size of the packets sent to the addPacket Channels
const PacketInformationCacheSize = 128

type Pools struct {
	pools []*pool
}

// Create new pools
func NewPools(tcpFilter, udpFilter []uint16, tcpDropIncomplete bool) *Pools {
	p := &Pools{}
	var tcpFilterList [65536]bool
	for _, i := range tcpFilter {
		tcpFilterList[i] = true
	}
	var udpFilterList [65536]bool
	for _, i := range udpFilter {
		udpFilterList[i] = true
	}
	p.pools = make([]*pool, NumFlowThreads)
	for i := 0; i < NumFlowThreads; i++ {
		p.pools[i] = newPool(&tcpFilterList, &udpFilterList, tcpDropIncomplete)
	}
	return p
}

// Returns the number of flow threads
func (p Pools) GetNumFlowThreads() int {
	return NumFlowThreads
}

// RegisterMetric registers a Metric which shall be called on flush
func (p *Pools) RegisterMetric(metric metrics.Metric) {
	for _, pool := range p.pools {
		pool.registerMetric(metric)
	}
}

// Add a TCP Packet to the pools
func (p *Pools) AddTCPPacket(packet *flows.PacketInformation) {
	poolIndex := uint64(packet.FlowKey) % NumFlowThreads
	p.pools[poolIndex].addTCPPacket(packet)
}

// Add a UDP Packet to the pools
func (p *Pools) AddUDPPacket(packet *flows.PacketInformation) {
	poolIndex := uint64(packet.FlowKey) % NumFlowThreads
	p.pools[poolIndex].addUDPPacket(packet)
}

// Flush out closed or timedout flows.
// If force is true, all Flows are flushed, else only timedout flows
func (p *Pools) Flush(force bool) {
	var wgFlush sync.WaitGroup
	var tcpFlushed int64
	var tcpCount int64
	var udpFlushed int64
	var udpCount int64
	var counterLock sync.Mutex
	for _, pool := range p.pools {
		pool.flush(force, &wgFlush, &tcpFlushed, &tcpCount, &udpFlushed, &udpCount, &counterLock)
	}
	//fmt.Println("waiting for flush")
	wgFlush.Wait()
	fmt.Println(humanize.Comma(tcpFlushed), "\t/", humanize.Comma(tcpCount), "TCP Flows flushed")
	fmt.Println(humanize.Comma(udpFlushed), "\t/", humanize.Comma(udpCount), "UDP Flows flushed")
	//p.PrintStatistics()
	fmt.Println()
	wgFlush.Wait()
}

// Close all pools and flush out all flows from pools.
func (p *Pools) Close() {
	for _, pool := range p.pools {
		pool.close()
	}
	p.Flush(true)
}

// PrintStatistics print some statistics about the pool
func (p *Pools) PrintStatistics() {
	var numTCPFlows int64
	var numTCPPackets int64
	var numUDPFlows int64
	var numUDPPackets int64
	var counterLock sync.Mutex
	for _, pool := range p.pools {
		pool.printStatistics(&numTCPFlows, &numTCPPackets, &numUDPFlows, &numUDPPackets, &counterLock)
	}

	fmt.Println("Number of TCP Flows in Pool:\t", humanize.Comma(numTCPFlows))
	fmt.Println("Number of TCP Packets in Pool:\t", humanize.Comma(numTCPPackets))

	fmt.Println("Number of UDP Flows in Pool:\t", humanize.Comma(numUDPFlows))
	fmt.Println("Number of UDP Packets in Pool:\t", humanize.Comma(numUDPPackets))
}
