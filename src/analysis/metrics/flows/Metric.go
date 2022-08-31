package flows

import (
	"encoding/json"
	"fmt"
	"github.com/dustin/go-humanize"
	"os"
	"path"
	"sync"
	"test.com/scale/src/analysis/flows"
	"test.com/scale/src/analysis/metrics/common"
	"time"
)

type Metric struct {
	computeRRPs  bool
	rrIdentifier *common.ReqResIdentifier

	exportChannel chan *string
	doneChannel   chan bool

	metrics   []registrableMetric
	rrMetrics []registrableRRMetric
}

type ExportableValue interface {
	export() map[string]interface{}
}

type registrableMetric interface {
	onFlush(flow *flows.Flow) ExportableValue
}

type registrableRRMetric interface {
	onFlush(flow *flows.Flow, reqRes []*common.RequestResponse) ExportableValue
}

func NewMetric(samplingRate int64, computeRRPs bool, exportBufferSize uint) *Metric {
	metric := &Metric{
		computeRRPs:   computeRRPs,
		exportChannel: make(chan *string, exportBufferSize),
		doneChannel:   make(chan bool),
	}

	metricFlowRate := newMetricFlowRate()
	metricFlowRate.samplingRate = samplingRate

	metric.addMetric(metricFlowRate)
	metric.addMetric(newMetricProtocol())
	metric.addMetric(newMetricFlowSize())
	metric.addMetric(newMetricPackets())
	metric.addMetric(newMetricFlowDuration())

	if !computeRRPs {
		return metric
	}

	metric.rrIdentifier = common.NewReqResIdentifier(
		false, false,
		nil, nil,
	)

	metric.addRRMetric(newMetricRRPs())

	return metric
}

func (m *Metric) addMetric(metric registrableMetric) {
	m.metrics = append(m.metrics, metric)
}

func (m *Metric) addRRMetric(rrMetric registrableRRMetric) {
	m.rrMetrics = append(m.rrMetrics, rrMetric)
}

// Callback that is called by the pools, once reconstruction for a flow is done.
// This means that this method runs concurrently.
func (m *Metric) OnTCPFlush(flow *flows.TCPFlow) {
	var protocol = common.GetProtocol(&flow.Flow)
	var rr = make([]*common.RequestResponse, 0)
	var dropFlow bool

	if m.computeRRPs {
		rr, dropFlow = m.rrIdentifier.OnTCPFlush(protocol, flow)
		if dropFlow {
			return
		}
	}

	m.onFlush(&flow.Flow, rr) // here i only give on the father flow object
}

// Callback that is called by the pools, once reconstruction for a flow is done.
// This means that this method runs concurrently.
func (m *Metric) OnUDPFlush(flow *flows.UDPFlow) {
	var protocol = common.GetProtocol(&flow.Flow)
	var rr = make([]*common.RequestResponse, 0)
	var dropFlow bool

	if m.computeRRPs {
		rr, dropFlow = m.rrIdentifier.OnUDPFlush(protocol, flow)
		if dropFlow {
			return
		}
	}

	m.onFlush(&flow.Flow, rr)
}

// This method is called by the callback. Simplifies metric implementation, as
// they are not required to implement different methods for TCP/UDP.
func (m *Metric) onFlush(flow *flows.Flow, rr []*common.RequestResponse) {
	values := make([]ExportableValue, len(m.metrics)+len(m.rrMetrics))

	for i, metric := range m.metrics {
		values[i] = metric.onFlush(flow)
	}

	if m.computeRRPs {
		for i, rrMetric := range m.rrMetrics {
			values[len(m.metrics)+i] = rrMetric.onFlush(flow, rr)
		}
	}

	combinedMetric := combineMetrics(values)
	m.exportChannel <- serializeMetric(combinedMetric)
}

// Combines metrics that have been computed independently into one.
func combineMetrics(values []ExportableValue) *map[string]interface{} {
	combinedMetric := make(map[string]interface{})

	for _, value := range values {
		for key, value := range value.export() {
			combinedMetric[key] = value
		}
	}

	return &combinedMetric
}

type LockedMetric struct {
	mu     sync.Mutex
	metric *map[string]interface{}
}

// Serializes a combined metric into a JSON string.
func serializeMetric(metric *map[string]interface{}) *string {
	/*
		test := *metric
		if data, ok := test["tcpOptionsClient"]; ok {
			//fmt.Println("no tcpOptionsClient")
			data_real := data.([]layers.TCPOption)
			if len(data_real) > 0 && cap(data_real) > 0 {
				//fmt.Println("maybe the error?")
				for i := 0; i < len(data_real); i++ {
					if data_real[i].OptionType == layers.TCPOptionKindTimestamps && data_real[i].OptionLength == 10 {
						fmt.Println("testcrash clienbt?")
					}

				}
			}
			//fmt.Println(data)
		} else {
			fmt.Println("no tcpOptionsClient")
		}

		if data, ok := test["tcpOptionsServer"]; ok {
			//fmt.Println("no tcpOptionsClient")
			data_real := data.([]layers.TCPOption)
			if len(data_real) > 0 && cap(data_real) > 0 {
				//fmt.Println("maybe the error?")
				for i := 0; i < len(data_real); i++ {
					if data_real[i].OptionType == layers.TCPOptionKindTimestamps && data_real[i].OptionLength == 10 {
						fmt.Println("testcrash server?")
					}

				}
			}
			//fmt.Println(data)
		} else {
			fmt.Println("no tcpOptionsServer")
		}

		if data, ok := test["TCPOptionsinFlow"]; ok {
			//fmt.Println("no tcpOptionsClient")
			data_real_inter := data.([][]layers.TCPOption)
			for i_j := 0; i_j < len(data_real_inter); i_j++ {
				if len(data_real_inter[i_j]) > 0 && cap(data_real_inter[i_j]) > 0 {
					//fmt.Println("maybe the error?")
					for i := 0; i < len(data_real_inter[i_j]); i++ {
						if data_real_inter[i_j][i].OptionType == layers.TCPOptionKindTimestamps && data_real_inter[i_j][i].OptionLength == 10 {
							fmt.Println("testcrash? flow")
						}
					}
				}
			}
			//fmt.Println(data)
		} else {
			fmt.Println("no TCPOptionsinFlow")
		}

		if data, ok := test["size"]; ok {
			if data := data.(uint); data == 0 {
				fmt.Println("size is 0")
			}
		}
		/*test, ok := metric["tcpOptionsClient"]
		if test != 0 {
			delete(metric*, "tcpOptionsClient")
		}*/
	//fmt.Println("go next marshal")

	/*mopre test code
	test := *metric
	if data, ok := test["tcpOptionsServer"]; ok {
		//fmt.Println("no tcpOptionsClient")
		data_real := data.([]layers.TCPOption)
		if len(data_real) > cap(data_real) {
			fmt.Println(test)

		}
	}*/
	dummy := new(LockedMetric)
	dummy.metric = metric
	dummy.mu.Lock()
	b, err := json.Marshal(dummy.metric)
	//fmt.Println("marshal done")
	//fmt.Println("")
	dummy.mu.Unlock()
	if err != nil {
		fmt.Println(err.Error())
		panic("Error during json marshalling!")
	}

	serialized := string(b)
	return &serialized
}

// Closes the exportChannel, which causes all buffered metrics to be flushed.
func (m *Metric) Flush() {
	close(m.exportChannel)
}

// Waits until all metrics have been written to file.
func (m *Metric) Wait() {
	<-m.doneChannel
}

// Should always be called as a goroutine. Writes serialized metrics directly to disk.
func (m *Metric) ExportRoutine(directory string) {
	filename := path.Join(directory, "flow_metrics.json")
	if _, err := os.Stat(filename); err == nil {
		// File exists
		err := os.Remove(filename)
		if err != nil {
			fmt.Println(err.Error())
			panic("Could not remove '" + filename + "'!")
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(err.Error())
		panic("Could not create '" + filename + "'!")
	}

	err = os.Chmod(filename, 0644)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("Could not change permissions for '" + filename + "'!")
	}

	fmt.Println("Export routine successfully setup.")
	start := time.Now()

	/*_, err = f.WriteString("{")
	if err != nil {
		fmt.Println(err.Error())
		panic("Error writing to file!")
	}*/

	id := 0
	serializedMetric := ""
	for serializedMetricPointer := range m.exportChannel {
		if len(serializedMetric) != 0 {
			//_, err = f.WriteString(fmt.Sprintf("\"%d\":%s,", id, serializedMetric)) if i want to rennable alos look upP!
			_, err = f.WriteString(fmt.Sprintf("%s\n", serializedMetric))
			if err != nil {
				fmt.Println(err.Error())
				panic("Error writing to file!")
			}
		}

		serializedMetric = *serializedMetricPointer
		id++
	}

	//_, err = f.WriteString(fmt.Sprintf("\"%d\":%s}", id, serializedMetric))
	_, err = f.WriteString(fmt.Sprintf("%s", serializedMetric))
	if err != nil {
		fmt.Println(err.Error())
		panic("Error writing to file!")
	}

	err = f.Close()
	if err != nil {
		fmt.Println(err.Error())
		panic("Error closing file!")
	}

	fmt.Println("Finished writing json. Took:\t", time.Since(start))
	fmt.Printf("Export successful. Exported:\t %s flow metrics", humanize.Comma(int64(id)))

	m.doneChannel <- true
	close(m.doneChannel)
}
