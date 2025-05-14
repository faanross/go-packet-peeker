package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"image/color"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

const defaultHistogramBins = 50

func main() {
	// Parse CLA
	pcapFile := flag.String("f", "", "Path to the pcap or pcapng file")
	flag.Parse()
	if *pcapFile == "" {
		log.Fatal("Error: pcap file path is required. Use -f <filepath>")
	}

	// Initial scan for: total packet count, source IPs, destination IPs
	fmt.Println("Performing initial scan...")
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap file for initial scan: %v", err)
	}
	packetSource1 := gopacket.NewPacketSource(handle, handle.LinkType())
	initialPacketCount := 0
	allSourceIPsMap := make(map[string]struct{})
	allDestIPsMap := make(map[string]struct{})
	for packet := range packetSource1.Packets() {
		initialPacketCount++
		var srcIP, dstIP string
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
		}
		if srcIP != "" {
			allSourceIPsMap[srcIP] = struct{}{}
		}
		if dstIP != "" {
			allDestIPsMap[dstIP] = struct{}{}
		}
	}
	handle.Close()
	fmt.Println("\n--- Initial Analysis Complete ---")
	fmt.Printf("Total packets in file: %d\n", initialPacketCount)
	getSortedIPs := func(ipMap map[string]struct{}) []string {
		ips := make([]string, 0, len(ipMap))
		for ip := range ipMap {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		return ips
	}
	sourceIPsList := getSortedIPs(allSourceIPsMap)
	destIPsList := getSortedIPs(allDestIPsMap)
	if len(sourceIPsList) == 0 || len(destIPsList) == 0 {
		log.Println("Warning: No source or destination IPs found in the pcap file.")
		// Allow continuing if one list is empty, selection will handle it
	}

	// Select Host Pair for Protocol Analysis
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n--- Select IPs for Flow Analysis ---")
	selectedSourceIP, err := selectFromList(sourceIPsList, "Select Source IP:", reader)
	if err != nil {
		log.Fatalf("Could not select Source IP: %v. Exiting.", err)
	}
	selectedDestIP, err := selectFromList(destIPsList, "\nSelect Destination IP:", reader)
	if err != nil {
		log.Fatalf("Could not select Destination IP: %v. Exiting.", err)
	}
	fmt.Printf("Source IP: %s, Destination IP: %s\n", selectedSourceIP, selectedDestIP)

	fmt.Printf("\nAnalyzing flow from %s to %s for protocol breakdown...\n", selectedSourceIP, selectedDestIP)
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap for second pass: %v", err)
	}
	packetSource2 := gopacket.NewPacketSource(handle, handle.LinkType())
	flowPacketCount := 0
	protocolCounts := make(map[string]int)
	for packet := range packetSource2.Packets() {
		var currentSrcIP, currentDstIP string
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		}
		if currentSrcIP == selectedSourceIP && currentDstIP == selectedDestIP {
			flowPacketCount++
			protocolCounts[getPacketProtocol(packet)]++
		}
	}
	handle.Close()
	fmt.Println("\n--- Flow Protocol Analysis Complete ---")
	fmt.Printf("Total packets from %s to %s: %d\n", selectedSourceIP, selectedDestIP, flowPacketCount)
	if flowPacketCount == 0 {
		fmt.Println("No packets found for the selected source and destination IP pair. Exiting.")
		return
	}
	fmt.Println("\nProtocol Breakdown:")
	sortedProtocols := getSortedKeys(protocolCounts)
	for _, p := range sortedProtocols {
		fmt.Printf("  - %s: %d\n", p, protocolCounts[p])
	}
	if len(sortedProtocols) == 0 {
		fmt.Println("No protocols identified for the selected flow. Exiting.")
		return
	}

	// Select specific protocol to generate Histogram
	fmt.Println("\n--- Select Protocol for Histogram & Payload Analysis ---")
	selectedProtocol, err := selectFromList(sortedProtocols, "Select Protocol:", reader)
	if err != nil {
		log.Fatalf("Could not select Protocol: %v. Exiting.", err)
	}
	fmt.Printf("Protocol selected: %s\n", selectedProtocol)

	fmt.Printf("\nAnalyzing flow for packet sizes (Proto: %s)...\n", selectedProtocol)
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap for third pass: %v", err)
	}
	packetSource3 := gopacket.NewPacketSource(handle, handle.LinkType())
	var packetSizes []float64
	for packet := range packetSource3.Packets() {
		var currentSrcIP, currentDstIP string
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		}
		if currentSrcIP == selectedSourceIP && currentDstIP == selectedDestIP && getPacketProtocol(packet) == selectedProtocol {
			packetSizes = append(packetSizes, float64(packet.Metadata().CaptureInfo.CaptureLength))
		}
	}
	handle.Close()
	if len(packetSizes) > 0 {
		histTitle := fmt.Sprintf("Packet Size Distribution\nSrc: %s, Dst: %s\nProto: %s", selectedSourceIP, selectedDestIP, selectedProtocol)
		if err := saveHistogram(packetSizes, "result.png", histTitle); err != nil {
			log.Printf("Warning: Could not generate histogram: %v\n", err)
		}
	} else {
		fmt.Println("No packets found for histogram for the selected flow and protocol.")
	}

	// Finally, provide range for payload dumping
	fmt.Println("\n--- Enter Packet Size Range for Payload Analysis ---")
	minSize, err := getIntInput(fmt.Sprintf("Enter minimum packet size (for %s flow): ", selectedProtocol), reader)
	if err != nil {
		log.Fatalf("Error getting min size: %v", err)
	}
	maxSize, err := getIntInput(fmt.Sprintf("Enter maximum packet size (for %s flow): ", selectedProtocol), reader)
	if err != nil {
		log.Fatalf("Error getting max size: %v", err)
	}
	if minSize > maxSize {
		log.Fatal("Error: Minimum size cannot be greater than maximum size.")
	}
	fmt.Printf("Analyzing payloads for packets between %d and %d bytes.\n", minSize, maxSize)

	//  PAYLOAD PROCESSING AND CSV OUTPUT
	reportFileName := "cleaned_unique_payloads.csv"
	reportFile, err := os.Create(reportFileName)
	if err != nil {
		log.Fatalf("Error creating report file %s: %v", reportFileName, err)
	}
	defer reportFile.Close()

	csvWriter := csv.NewWriter(reportFile)
	defer csvWriter.Flush()

	fmt.Printf("\nExtracting, cleaning, and collecting payloads from %s...\n", *pcapFile)
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap for payload pass: %v", err)
	}
	defer handle.Close()

	packetSource4 := gopacket.NewPacketSource(handle, handle.LinkType())
	collectedCleanedPayloads := make(map[string]struct{})

	packetsProcessedForPayload := 0
	for packet := range packetSource4.Packets() {
		var currentSrcIP, currentDstIP string
		packetSize := packet.Metadata().CaptureInfo.CaptureLength

		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			currentSrcIP, currentDstIP = ip.SrcIP.String(), ip.DstIP.String()
		}

		if currentSrcIP == selectedSourceIP &&
			currentDstIP == selectedDestIP &&
			getPacketProtocol(packet) == selectedProtocol &&
			packetSize >= minSize && packetSize <= maxSize {

			packetsProcessedForPayload++
			var rawPayloadString string
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payloadBytes := appLayer.Payload()
				if len(payloadBytes) > 0 {
					rawPayloadString = printableASCIIPayload(payloadBytes)
				}
			} else {
				var payloadBytes []byte
				if tcp := packet.TransportLayer(); tcp != nil {
					payloadBytes = tcp.LayerPayload()
				} else if udp := packet.TransportLayer(); udp != nil {
					payloadBytes = udp.LayerPayload()
				} else if icmp := packet.Layer(layers.LayerTypeICMPv4); icmp != nil {
					if icmpV4, ok := icmp.(*layers.ICMPv4); ok {
						payloadBytes = icmpV4.Payload
					}
				} else if icmp6 := packet.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
					if icmpV6Concrete, ok := icmp6.(*layers.ICMPv6); ok {
						payloadBytes = icmpV6Concrete.LayerPayload()
					}
				}
				if len(payloadBytes) > 0 {
					rawPayloadString = printableASCIIPayload(payloadBytes)
				}
			}

			if rawPayloadString != "" {
				cleanedPayload := cleanPayloadPrefix(rawPayloadString)
				if cleanedPayload != "" {
					collectedCleanedPayloads[cleanedPayload] = struct{}{}
				}
			}
		}
	}

	if packetsProcessedForPayload == 0 {
		fmt.Printf("\nNo packets matched the criteria for payload extraction (IPs, Protocol, Size Range: %d-%d bytes).\n", minSize, maxSize)
	}

	if len(collectedCleanedPayloads) == 0 {
		fmt.Printf("No valid payloads found or remained after cleaning from %d processed packets.\n", packetsProcessedForPayload)
		fmt.Println("\nAnalysis finished.")
		return
	}

	// Convert map keys (unique cleaned payloads) to a slice for sorting
	finalPayloadsList := make([]string, 0, len(collectedCleanedPayloads))
	for p := range collectedCleanedPayloads {
		finalPayloadsList = append(finalPayloadsList, p)
	}

	// Sort the unique cleaned payloads alphabetically (ascending)
	sort.Strings(finalPayloadsList)

	// Write the header and the sorted unique cleaned payloads to the CSV
	headerRecord := []string{"Cleaned Unique Payload"}
	if err := csvWriter.Write(headerRecord); err != nil {
		log.Fatalf("Error writing CSV header to %s: %v", reportFileName, err)
	}

	for _, payloadEntry := range finalPayloadsList {
		record := []string{payloadEntry}
		if err := csvWriter.Write(record); err != nil {
			log.Printf("Warning: Error writing payload '%s' to CSV: %v\n", payloadEntry, err)
		}
	}

	fmt.Printf("\nPayload processing complete. %d unique cleaned payloads written to %s\n", len(finalPayloadsList), reportFileName)
	fmt.Println("\nAnalysis finished.")
}

// cleanPayloadPrefix removes the unwanted prefix from the payload string.
// It looks for the first sequence of 5 or more dots, then finds the end
// of that dot sequence, and returns everything after it.
func cleanPayloadPrefix(payload string) string {
	// Minimum number of dots to trigger the prefix removal
	const minDots = 5
	dotSequence := strings.Repeat(".", minDots)

	startIndex := strings.Index(payload, dotSequence)

	if startIndex == -1 {
		// If the sequence of 5 dots isn't found, return the payload as is.
		return payload
	}

	endOfDotSequenceIndex := startIndex
	for endOfDotSequenceIndex < len(payload) && payload[endOfDotSequenceIndex] == '.' {
		endOfDotSequenceIndex++
	}

	// If dots go to the end of the string, or nothing is after, return empty.
	if endOfDotSequenceIndex >= len(payload) {
		return ""
	}

	// Return the part of the string after this sequence of dots.
	// Trim leading space from the actual content.
	return strings.TrimSpace(payload[endOfDotSequenceIndex:])
}

// Helper function to get integer input from the user
func getIntInput(prompt string, reader *bufio.Reader) (int, error) {
	fmt.Print(prompt)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		val, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf("Invalid input. Please enter a whole number: ")
			continue
		}
		return val, nil
	}
}

// Helper function to convert payload bytes to a printable ASCII string
func printableASCIIPayload(payload []byte) string {
	var result strings.Builder
	for _, b := range payload {
		if b >= 32 && b <= 126 { // Standard printable ASCII
			result.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' { // Allow common whitespace
			result.WriteByte(b)
		} else {
			result.WriteRune('.') // Replace non-printable with a dot
		}
	}
	return result.String()
}

// Helper function to convert map keys (IPs or protocols) to a sorted slice
func getSortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Helper function to get user selection from a list of strings
func selectFromList(list []string, prompt string, reader *bufio.Reader) (string, error) {
	if len(list) == 0 {
		return "", fmt.Errorf("list is empty, cannot select")
	}
	fmt.Println(prompt)
	for i, item := range list {
		fmt.Printf("  %d: %s\n", i+1, item)
	}
	fmt.Print("Enter number: ")
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(list) {
			fmt.Printf("Invalid input. Please enter a number between 1 and %d: ", len(list))
			continue
		}
		return list[choice-1], nil
	}
}

// Function to determine the protocol of a packet
func getPacketProtocol(packet gopacket.Packet) string {
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		return "DNS"
	}
	if app := packet.ApplicationLayer(); app != nil {
		payload := string(app.Payload())
		if strings.HasPrefix(payload, "HTTP/") ||
			strings.HasPrefix(payload, "GET ") ||
			strings.HasPrefix(payload, "POST ") ||
			strings.HasPrefix(payload, "PUT ") ||
			strings.HasPrefix(payload, "DELETE ") ||
			strings.HasPrefix(payload, "HEAD ") {
			return "HTTP"
		}
	}
	if packet.Layer(layers.LayerTypeTLS) != nil {
		return "TLS"
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if packet.Layer(layers.LayerTypeTLS) == nil {
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				return "HTTP (TCP Port 80)"
			}
			if tcp.DstPort == 443 || tcp.SrcPort == 443 {
				return "HTTPS (TCP Port 443)"
			}
		}
		return "TCP"
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if packet.Layer(layers.LayerTypeDNS) == nil {
			if udp.DstPort == 53 || udp.SrcPort == 53 {
				return "DNS (UDP Port 53)"
			}
		}
		return "UDP"
	}
	if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp4, _ := icmp4Layer.(*layers.ICMPv4)
		return fmt.Sprintf("ICMPv4 (Type %02d)", icmp4.TypeCode.Type())
	}
	if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		return fmt.Sprintf("ICMPv6 (Type %02d)", icmp6.TypeCode.Type())
	}
	if packet.NetworkLayer() != nil {
		return "IP (Other)"
	}
	return "Other"
}

// Function to generate and save a histogram
func saveHistogram(sizes []float64, filename string, plotTitle string) error {
	if len(sizes) == 0 {
		fmt.Println("No data to plot for histogram.")
		return nil
	}
	p := plot.New()
	p.Title.Text = plotTitle
	p.X.Label.Text = "Packet Size (bytes)"
	p.Y.Label.Text = "Number of Packets (Count)"

	p.Title.Padding = vg.Points(10)
	p.X.Padding = 0
	p.Y.Padding = 0

	v := make(plotter.Values, len(sizes))
	for i, size := range sizes {
		v[i] = size
	}
	h, err := plotter.NewHist(v, defaultHistogramBins)
	if err != nil {
		return fmt.Errorf("could not create histogram: %v", err)
	}
	h.FillColor = color.RGBA{R: 255, G: 153, B: 0, A: 255}
	h.Color = color.RGBA{A: 255}
	p.Add(h)

	if err := p.Save(12*vg.Inch, 9*vg.Inch, filename); err != nil {
		return fmt.Errorf("could not save plot: %v", err)
	}
	fmt.Printf("Histogram saved to %s\n", filename)
	return nil
}
