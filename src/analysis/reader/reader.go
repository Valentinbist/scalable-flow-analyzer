package reader

import (
	"fmt"
	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"strings"
	"test.com/scale/src/analysis/parser"
	"test.com/scale/src/analysis/pool"
	"test.com/scale/src/analysis/utils"
)

// PacketReader reads from a source.
// Is responsible for forwarding packets to the parser,
// as well as keeping track of the number of Packet, as well
// as flushing the pool in regular intervals.
type PacketReader struct {
	PacketIdx            int64
	flushTimestamp       int64
	FirstPacketTimestamp int64
	LastPacketTimestamp  int64
	pools                *pool.Pools
	parser               *parser.Parser
}

// NewPacketReader creates a new PacketReader.
func NewPacketReader(pools *pool.Pools, packetParser *parser.Parser) *PacketReader {
	return &PacketReader{
		pools:  pools,
		parser: packetParser,
	}
}

// Read more packets from the provided source.
// Will stop either when the source is depleted
// or when the specified number of packets have been read.
// Use first return value of ReadPCAPFile to read a pcap file.
// flushRate specifies the time in nanoseconds after which pools will be flushed.
// Flushing the pool is necessary to remove timedout flows from the pool
// and to keep memory footprint low.
//
// Returns whether the specified number of packets have been read
func (p *PacketReader) Read(packetStop, flushRate int64, packetDataSource gopacket.PacketDataSource) bool {
	spike_count := 0
	for p.PacketIdx < packetStop {
		data, ci, err := packetDataSource.ReadPacketData()
		// Stop reading at end of file
		if err == io.EOF {
			return false
		}

		if p.PacketIdx == 0 {
			p.FirstPacketTimestamp = ci.Timestamp.UnixNano()
			p.flushTimestamp = p.FirstPacketTimestamp + flushRate
		}

		if err != nil {
			//fmt.Println("Error reading packet: ", err) todo renable and filter out
			continue
		}
		if len(data) == 0 { //sometimes packets with len 0 come thorugh although no error is thrown? these have weird timestamps
			continue
		}
		p.PacketIdx++

		// Setup Flushing Interval
		p.LastPacketTimestamp = ci.Timestamp.UnixNano()

		/*
			p.PacketIdx++
			if err != nil {
				fmt.Println("Error reading packet: ", err)
				continue
			} moved the error handling up */
		// Parse packet
		p.parser.ParsePacket(data, p.PacketIdx, p.LastPacketTimestamp)
		// Flush packet when flushing interval is reached
		if p.LastPacketTimestamp > p.flushTimestamp {
			// print flush timestamp in human readable format

			if p.LastPacketTimestamp-p.flushTimestamp >= flushRate*3 {
				if spike_count > 1000 { // if we have over 1000 spikes, this is not a spike but just the data i guess, so give it a try
					fmt.Println("1000 spikes, trying to continue softly")
					p.flushTimestamp = p.flushTimestamp + flushRate

				} else {
					fmt.Println("spike?")
					spike_count += 1
					continue
				}
			} else {
				p.flushTimestamp = p.LastPacketTimestamp + flushRate
			}
			fmt.Println("Flushing pool at: ", humanize.Comma(p.LastPacketTimestamp))

			spike_count = 0
			// print new flush timesamp in human readable format
			//fmt.Println("Next flush at: ", humanize.Comma(p.flushTimestamp))
			//utils.PrintMemUsage()
			//utils.CreateMemoryProfile(strconv.FormatInt(p.flushTimestamp, 10))
			fmt.Println("Flush at packet", humanize.Comma(p.PacketIdx))
			p.pools.Flush(false)
		}
	}
	return true
}

// ReadPcapFile reads a pcap/pcapng file from filename. This file can optionally be zipped.
//
// Returns an instance of NgReader to read the pcap.
// Also returns an io.ReadCloser which must be closed after the file has been read.
// file is not nil for zipped file. If it is not nil, the caller must close it.
func ReadPcapFile(filename string) (reader gopacket.PacketDataSource, ioReader io.ReadCloser, deleteFile bool, deleteFileName string) {
	if strings.Contains(filename, ".pcapng") {
		return readPcapNgFile(filename)
	} else {
		return readPcapFile(filename)
	}
}

// readPcapFile reads a pcap file from filename. This file can optionally be zipped.
//
// Returns an instance of NgReader to read the pcap.
// Also returns an io.ReadCloser which must be closed after the file has been read.
// file is not nil for zipped file. If it is not nil, the caller must close it.
func readPcapFile(filename string) (reader *pcapgo.Reader, ioReader io.ReadCloser, deleteFile bool, deleteFileName string) {
	var err error

	if utils.IsZipFile(filename) {
		unzippedFileName := utils.Unzip(filename)
		ioReader, err = os.Open(unzippedFileName)
		deleteFile = true
		deleteFileName = unzippedFileName
	} else {
		ioReader, err = os.Open(filename)
	}

	if err != nil {
		log.Fatal(err)
	}

	reader, err = pcapgo.NewReader(ioReader)

	if err != nil {
		panic(err)
	}

	return reader, ioReader, deleteFile, deleteFileName
}

// readPcapNgFile reads a pcapng file from filename. This file can optionally be zipped.
//
// Returns an instance of NgReader to read the pcap.
// Also returns an io.ReadCloser which must be closed after the file has been read.
// file is not nil for zipped file. If it is not nil, the caller must close it.
func readPcapNgFile(filename string) (ngReader *pcapgo.NgReader, ioReader io.ReadCloser, deleteFile bool, deleteFileName string) {
	var err error

	if utils.IsZipFile(filename) {
		unzippedFileName := utils.Unzip(filename)
		ioReader, err = os.Open(unzippedFileName)
		deleteFile = true
		deleteFileName = unzippedFileName
	} else {
		ioReader, err = os.Open(filename)
	}

	if err != nil {
		log.Fatal(err)
	}

	ngReader, err = pcapgo.NewNgReader(ioReader, pcapgo.DefaultNgReaderOptions)

	if err != nil {
		panic(err)
	}
	return ngReader, ioReader, deleteFile, deleteFileName
}
