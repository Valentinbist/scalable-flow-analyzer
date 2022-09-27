package parser

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"test.com/scale/src/analysis/flows"
	"test.com/scale/src/analysis/pool"
	"time"

	"github.com/cespare/xxhash"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parserChannelSize defines the Size of the channel to the Parser
const parserChannelSize = 40000

// packetDataCacheSize is the batching size of the packets sent to the Parsers
const packetDataCacheSize = 1200

const ringBufferFlushChannelSize = 200

// Parser multithreads parsing of packets
type Parser struct {
	numFlowThreads       uint64
	parsePacketDataCache packetDataCache
	pool                 *pool.Pools
	samplingrate         float64
	numParserChannel     int
	parserChannel        []chan [packetDataCacheSize]PacketData

	ringbufferUsedlist     []bool // Same size as ringbuffer. Indicates whether a ringbuffer entry is used or not
	ringbuffer             []flows.PacketInformation
	ringbufferStart        int64
	ringbufferSize         int64
	ringbufferFlushChannel chan bool

	wgParserThreads   sync.WaitGroup // Waitgroup to wait until parser are finished
	wgRingbufferFlush sync.WaitGroup // Waitgroup to wait until Ringbuffer is flushed
}

// PacketData contains the basic information from the packet source
type PacketData struct {
	Data        []byte
	Timestamp   int64
	PacketIdx   int64
	InterfaceID uint8
}

type packetDataCache struct {
	buf [packetDataCacheSize]PacketData
	pos int
}

// NewParser returns a new parser
func NewParser(p *pool.Pools, sortingRingBufferSize int64, numParserThreads int, samplingrate float64, numParserChannel int) *Parser {
	var parser = &Parser{
		pool:                   p,
		samplingrate:           samplingrate,
		numParserChannel:       int(math.Min(float64(numParserChannel), float64(numParserThreads))),
		parsePacketDataCache:   packetDataCache{},
		ringbufferUsedlist:     make([]bool, sortingRingBufferSize),
		ringbuffer:             make([]flows.PacketInformation, sortingRingBufferSize),
		ringbufferStart:        1,
		ringbufferSize:         sortingRingBufferSize,
		ringbufferFlushChannel: make(chan bool, ringBufferFlushChannelSize),
		numFlowThreads:         uint64(p.GetNumFlowThreads()),
	}
	parser.wgParserThreads.Add(numParserThreads)
	parser.parserChannel = make([]chan [packetDataCacheSize]PacketData, parser.numParserChannel)
	for i := 0; i < numParserChannel; i++ {
		parser.parserChannel[i] = make(chan [packetDataCacheSize]PacketData, parserChannelSize)
	}
	for i := 0; i < numParserThreads; i++ {
		go parser.parsePacket(parser.parserChannel[i%parser.numParserChannel], i)
	}
	parser.wgRingbufferFlush.Add(1)
	go parser.flushRingbuffer()
	return parser
}

// Close Parser and flush out all packets to the pool
func (p *Parser) Close() {
	// Flush to parser
	tmpPacketsCache := packetDataCache{}
	copy(tmpPacketsCache.buf[:p.parsePacketDataCache.pos], p.parsePacketDataCache.buf[:p.parsePacketDataCache.pos])
	p.parserChannel[0] <- tmpPacketsCache.buf
	// Close Parser
	for i := 0; i < p.numParserChannel; i++ {
		close(p.parserChannel[i])
	}
	p.wgParserThreads.Wait()

	// Ensure to flush out all remaining packets from the sorting ringbuffer
	p.ringbufferFlushChannel <- true
	close(p.ringbufferFlushChannel)
	p.wgRingbufferFlush.Wait()
}

// ParsePacket adds a packet to the parser (buffered)
func (p *Parser) ParsePacket(data []byte, packetIdx, packetTimestamp int64, interfaceID uint8) {
	p.parsePacketDataCache.buf[p.parsePacketDataCache.pos] = PacketData{Data: data, PacketIdx: packetIdx, Timestamp: packetTimestamp, InterfaceID: interfaceID}
	p.parsePacketDataCache.pos++
	if p.parsePacketDataCache.pos == packetDataCacheSize {
		p.parserChannel[rand.Intn(p.numParserChannel)] <- p.parsePacketDataCache.buf
		p.parsePacketDataCache.pos = 0
	}
}

// parsePacket is the internal method, called when the internal cache/buffer is full
func (p *Parser) parsePacket(channel chan [packetDataCacheSize]PacketData, parserIndex int) {
	var dot1q layers.Dot1Q
	var gre layers.GRE
	var eth layers.Ethernet

	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var ipv6e layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var udp layers.UDP
	var samplingModulo uint64 = 1
	// ensure that modulo is really 1, when 100 percent sampling rate (due to float conversion)
	if p.samplingrate != 100 {
		samplingModulo = uint64(float64(p.numFlowThreads) * (100 / p.samplingrate))
	}

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&dot1q, &eth, &gre, &ipv4, &ipv6, &ipv6e, &tcp, &udp)
	parserIPv4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4, &tcp, &udp)
	parserIPv6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ipv6, &ipv6e, &tcp, &udp)
	var decoded []gopacket.LayerType
	for packets := range channel {
		for _, packet := range &packets {
			// Ignore empty packets from last flush
			if packet.PacketIdx == 0 {
				continue
			}
			_ = parserIPv4.DecodeLayers(packet.Data, &decoded)
			if len(decoded) < 2 {
				_ = parser.DecodeLayers(packet.Data, &decoded)
				if len(decoded) < 2 {
					_ = parserIPv6.DecodeLayers(packet.Data, &decoded)
				}
			}
			packetInfo := flows.PacketInformation{Timestamp: packet.Timestamp, PacketIdx: packet.PacketIdx, InterfaceId: packet.InterfaceID}
			var ipLength uint16
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					ipLength = ipv4.Length - (uint16(ipv4.IHL) * 4)
					packetInfo.SrcIP = xxhash.Sum64(ipv4.SrcIP)
					packetInfo.DstIP = xxhash.Sum64(ipv4.DstIP)
					packetInfo.FullSrcIp = ipv4.SrcIP
					packetInfo.FullDstIp = ipv4.DstIP
				case layers.LayerTypeIPv6:
					ipLength = ipv6.Length
					// if zero
					if ipLength == 0 {
						fmt.Println("Jumbogram detected. Currently unsupported.")
					}
					// Subtract possible extension header length
					if len(ipv6e.Contents) != 0 {
						// since ipv6 can contain more than one extension header: search for last extens
						// TODO: search for last extension and remove them from iplength
						ipLength -= uint16(len(ipv6e.Contents))
						ipv6e.Contents = make([]byte, 0)
					}
					packetInfo.SrcIP = xxhash.Sum64(ipv6.SrcIP)
					packetInfo.DstIP = xxhash.Sum64(ipv6.DstIP)
					packetInfo.FullSrcIp = ipv6.SrcIP
					packetInfo.FullDstIp = ipv6.DstIP
				case layers.LayerTypeTCP:
					packetInfo.HasTCP = true
					packetInfo.TCPSYN = tcp.SYN
					packetInfo.TCPACK = tcp.ACK
					packetInfo.TCPRST = tcp.RST
					packetInfo.TCPFIN = tcp.FIN
					packetInfo.SrcPort = uint16(tcp.SrcPort)
					packetInfo.DstPort = uint16(tcp.DstPort)
					packetInfo.TCPSeqNr = tcp.Seq
					packetInfo.TCPAckNr = tcp.Ack
					packetInfo.PayloadLength = ipLength - (uint16(tcp.DataOffset) * 4) // Data offset in 32 bits words
					packetInfo.FlowKey = GetFlowKey(packetInfo.SrcIP, packetInfo.DstIP, flows.TCP, packetInfo.SrcPort, packetInfo.DstPort)

					/*
						// old code
						//packetInfo.TCPOptions = tcp.Options
						//new code
						//irerate over tcp.Options
						if len(tcp.Options) > 0 && false == true {
							var tcpOptions_to_return []flows.CustomTCPOption
							//tcpOptions_to_return = make([]CustomTCPOption, 0)
							for _, option := range tcp.Options {
								//option_to_return := flows.CustomTCPOption{}
								dict_to_go := make(map[string]interface{})
								switch {
								case option.OptionType == layers.TCPOptionKindEndList && option.OptionLength == 1:
									// tcp option end list
									dict_to_go["type"] = 0

								case option.OptionType == layers.TCPOptionKindNop && option.OptionLength == 1:
									//option_to_return.Type = 1 // NOP
									dict_to_go["type"] = 1

								case option.OptionType == layers.TCPOptionKindMSS && option.OptionLength == 4:
									dict_to_go["type"] = 2 // MSS

									switch {
									case option.OptionData[0] == 5 && option.OptionData[1] == 180:
										dict_to_go["type"] = 255 + 21 // MSS base64 BbQ= hex. 05 B4
									case option.OptionData[0] == 2 && option.OptionData[1] == 24:
										dict_to_go["type"] = 255 + 22 // MSS hex. 02 18
									case option.OptionData[0] == 5 && option.OptionData[1] == 160:
										dict_to_go["type"] = 255 + 23 // MSS hex. 05 A0
									case option.OptionData[0] == 5 && option.OptionData[1] == 110:
										dict_to_go["type"] = 255 + 24 // MSS hex. 05 6E
									case option.OptionData[0] == 5 && option.OptionData[1] == 172:
										dict_to_go["type"] = 255 + 25 // MSS hex. 05 AC
									case option.OptionData[0] == 5 && option.OptionData[1] == 144:
										dict_to_go["type"] = 255 + 26 // MSS hex. 05 90
									default:
										dict_to_go["data"] = hex.EncodeToString(option.OptionData)
										//dict_to_go["data"] = option.OptionData
									}
								case option.OptionType == layers.TCPOptionKindWindowScale && option.OptionLength == 3:
									dict_to_go["type"] = 3 // Window Scale

									switch {
									case option.OptionData[0] == 7:
										dict_to_go["type"] = 255 + 37 // Window Scale 7
									case option.OptionData[0] == 8:
										dict_to_go["type"] = 255 + 38 // Window Scale 7
									case option.OptionData[0] == 0:
										dict_to_go["type"] = 255 + 30 // Window Scale 7
									case option.OptionData[0] == 2:
										dict_to_go["type"] = 255 + 32 // Window Scale 7
									case option.OptionData[0] == 1:
										dict_to_go["type"] = 255 + 31 // Window Scale 7
									case option.OptionData[0] == 3:
										dict_to_go["type"] = 255 + 33 // Window Scale 7
									case option.OptionData[0] == 4:
										dict_to_go["type"] = 255 + 34 // Window Scale 7
									case option.OptionData[0] == 5:
										dict_to_go["type"] = 255 + 35 // Window Scale 7
									case option.OptionData[0] == 6:
										dict_to_go["type"] = 255 + 36 // Window Scale 7
									case option.OptionData[0] == 9:
										dict_to_go["type"] = 255 + 39 // Window Scale 7

									default:
										dict_to_go["data"] = hex.EncodeToString(option.OptionData)
									}
								case option.OptionType == layers.TCPOptionKindSACKPermitted && option.OptionLength == 2:
									dict_to_go["type"] = 4 // SACK Permitted

								default:
									//option_to_return.TcpOption = option
									dict_to_go["type"] = option.OptionType
									dict_to_go["data"] = hex.EncodeToString(option.OptionData)
									dict_to_go["length"] = option.OptionLength

								}
								//option_to_return.Dict = dict_to_go

								//tcpOptions_to_return = AppendCustomOption(tcpOptions_to_return, dict_to_go)
								tcpOptions_to_return = append(tcpOptions_to_return, dict_to_go)
							}
							packetInfo.NewTCPOptions = tcpOptions_to_return

						}
					*/

					//packet
				case layers.LayerTypeUDP:
					packetInfo.HasUDP = true
					packetInfo.SrcPort = uint16(udp.SrcPort)
					packetInfo.DstPort = uint16(udp.DstPort)
					packetInfo.PayloadLength = udp.Length
					packetInfo.FlowKey = GetFlowKey(packetInfo.SrcIP, packetInfo.DstIP, flows.UDP, packetInfo.SrcPort, packetInfo.DstPort)
					/*
						case layers.LayerTypeEthernet:
							packetInfo.SrcInterface = eth.SrcMAC
							packetInfo.DstInterface = eth.DstMAC
							//if packetInfo.SrcInterface == "" {
							//	packetInfo.SrcInterface = "err"
							//}*/
				}
			}

			for packetInfo.PacketIdx-p.ringbufferStart > p.ringbufferSize {
				//p.flushRingbuffer()
				p.ringbufferFlushChannel <- true
				time.Sleep(1 * time.Second)
				fmt.Println("Parser", parserIndex, ": Sleep for 1s due to missing space in ringbuffer.")
				fmt.Println("Parser", parserIndex, ": Please increase sortingRingBufferSize variable or increase number of pool to speed up flushing if this happens more often.")
			}
			// Sampling
			if uint64(packetInfo.FlowKey)%samplingModulo > p.numFlowThreads {
				packetInfo.HasTCP = false
				packetInfo.HasUDP = false
			}
			ringBufferIndex := packetInfo.PacketIdx % p.ringbufferSize
			p.ringbuffer[ringBufferIndex] = packetInfo
			p.ringbufferUsedlist[ringBufferIndex] = true
		}
		if rand.Intn(100) <= 5 {
			p.ringbufferFlushChannel <- true
		}
	}
	p.wgParserThreads.Done()
}

// flushRingbuffer checks if packets can be flushed out to the processing unit.
func (p *Parser) flushRingbuffer() {
	for range p.ringbufferFlushChannel {
		// Go through ringbuffer and flush out all available packets

		//calculate the ringbuffer usage
		/*var ringbufferUsage int
		for _, used := range p.ringbufferUsedlist {
			if used {
				ringbufferUsage++
			}
		}
		fmt.Println("Ringbuffer usage before flush:", ringbufferUsage, "/", p.ringbufferSize)*/

		//var already_ran int64

		for i := p.ringbufferStart; true; i++ {
			ringBufferIndex := i % p.ringbufferSize
			/*already_ran++

			if already_ran > p.ringbufferSize {
				continue // todo is disabled, needs to be break to reenable
			}*/

			if !p.ringbufferUsedlist[ringBufferIndex] {
				p.ringbufferStart = i
				break
				// was break TODO change?
			}
			if p.ringbuffer[ringBufferIndex].HasTCP {
				p.pool.AddTCPPacket(&p.ringbuffer[ringBufferIndex])
			} else if p.ringbuffer[ringBufferIndex].HasUDP {
				p.pool.AddUDPPacket(&p.ringbuffer[ringBufferIndex])
			}
			p.ringbufferUsedlist[ringBufferIndex] = false
		}
		/*
			var ringbufferUsage int64
			ringbufferUsage = 0
			for _, used := range p.ringbufferUsedlist {
				if used {
					ringbufferUsage++
				}
			}
			if float64(ringbufferUsage)/float64(p.ringbufferSize) > 0.5 {
				fmt.Println("Ringbuffer usage after flush:", ringbufferUsage, "/", p.ringbufferSize)
				// find continous ares of used ring buffer indexes and print their start and end
				var start int64
				var end int64
				var found bool
				found = false
				for i := int64(0); i < p.ringbufferSize; i++ {
					if p.ringbufferUsedlist[i] {
						if !found {
							start = i
							found = true
						}
						end = i
					} else {
						if found {

							fmt.Println("Used ringbuffer indexes:", start, "-", end)
							fmt.Println("ringbuffer start", p.ringbufferStart)
							found = false
						}
					}
				}
				// print new line
				fmt.Println()*/
		/*
			if p.ringbufferUsedlist[(p.ringbufferStart+1)%p.ringbufferSize] == true {
				if p.ringbufferUsedlist[(p.ringbufferStart+int64(0.1*float64(p.ringbufferSize)))%p.ringbufferSize] == true { // cheap binary search
					if p.ringbufferUsedlist[(p.ringbufferStart+int64(0.5*float64(p.ringbufferSize)))%p.ringbufferSize] == true {
						p.ringbufferStart = p.ringbufferStart + 1 // if ringbuffer at 50 percent or above move this one packet ahead

						//then do this for debugging:
						// find continous ares of used ring buffer indexes and print their start and end
						var start int64
						var end int64
						var found bool
						var hits int8
						found = false
						for i := int64(0); i < p.ringbufferSize; i++ {
							if hits > 3 {
								fmt.Println("and more slices")
								break
							}
							if p.ringbufferUsedlist[i] {
								if !found {
									start = i
									found = true
								}
								end = i
							} else {
								if found {
									hits++
									fmt.Println("Used ringbuffer indexes:", start, "-", end)

									found = false
								}
							}
						}
						// print new line
						fmt.Println("ringbuffer start", p.ringbufferStart%p.ringbufferSize)
						fmt.Println()

					}
				}
			}*/

	}
	p.wgRingbufferFlush.Done()
}

// GetFlowKey returns the Flow key. Is symmetric so A:46254<-->B:80 returns the same key in both directions
func GetFlowKey(srcIP, dstIP uint64, protocol uint8, srcPort, dstPort uint16) flows.FlowKeyType {
	var app = make([]byte, 10)
	binary.LittleEndian.PutUint16(app, srcPort)
	binary.LittleEndian.PutUint64(app[2:], srcIP)
	var hashSrc = xxhash.Sum64(app)

	binary.LittleEndian.PutUint16(app, dstPort)
	binary.LittleEndian.PutUint64(app[2:], dstIP)
	var hashDst = xxhash.Sum64(app)
	return flows.FlowKeyType(hashSrc + uint64(protocol) + hashDst)
}
