# go-packet-peeker Usage Guide

This guide walks through the interactive analysis workflow.

## Prerequisites

### Installation

```bash
# Clone repository
git clone https://github.com/faanross/go-packet-peeker.git
cd go-packet-peeker

# Build
go build -o packet-peeker ./cmd/main.go
```

### Dependencies

The tool uses:
- `github.com/google/gopacket` - Packet parsing
- `gonum.org/v1/plot` - Histogram generation

Dependencies are managed via `go.mod`.

## Basic Usage

```bash
./packet-peeker -f /path/to/capture.pcapng
```

### Supported Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| PCAP | .pcap | Legacy format |
| PCAPng | .pcapng | Modern format (recommended) |

## Interactive Workflow

### Step 1: Load PCAP File

```bash
$ ./packet-peeker -f sample/icmp_tunnel.pcapng

Loading capture file...
Analyzing packets...
```

The tool opens the PCAP and begins the first pass.

### Step 2: Select Source IP

```
Found 5 unique source IPs:

1. 10.0.0.1
2. 10.0.0.50
3. 192.168.1.1
4. 192.168.1.100
5. 8.8.8.8

Select source IP (enter number): 2
```

Choose the IP address you want to analyze as the traffic source.

**Tips:**
- Internal IPs often indicate compromised hosts
- External IPs may be C2 servers
- Look for unexpected source IPs

### Step 3: Select Destination IP

```
Found 3 unique destination IPs for source 10.0.0.50:

1. 10.0.0.1
2. 192.168.1.1
3. 203.0.113.50

Select destination IP (enter number): 3
```

Choose the destination to complete the flow definition.

**Tips:**
- C2 traffic often goes to external IPs
- Internal destinations may indicate lateral movement
- Look for unusual destination ports/IPs

### Step 4: View Protocol Breakdown

```
Protocols detected in flow 10.0.0.50 → 203.0.113.50:

1. ICMPv4 (Type 08) - 150 packets
2. ICMPv4 (Type 00) - 150 packets
3. ICMPv4 (Type 03) - 47 packets

Select protocol (enter number): 3
```

The tool identifies all protocols used in the selected flow.

**Tips:**
- ICMP Type 03 (Destination Unreachable) with many packets is suspicious
- Balanced request/reply counts are normal
- Asymmetric traffic may indicate tunneling

### Step 5: View Histogram

After protocol selection, a histogram is generated:

```
Generating histogram...
Saved: result.png

Histogram shows packet size distribution.
```

**Interpreting the Histogram:**

| Pattern | Indication |
|---------|------------|
| Single peak | Normal traffic, consistent sizes |
| Bimodal (two peaks) | Possible covert channel |
| Wide distribution | Variable payload sizes |
| Unexpected large sizes | Data exfiltration |

### Step 6: Set Size Range

```
Enter minimum packet size (bytes): 100
Enter maximum packet size (bytes): 200
```

Focus on packets within a specific size range for payload extraction.

**Tips:**
- Use histogram to identify interesting ranges
- Target the "unusual" peak in bimodal distributions
- ICMP Type 3 should be 36-64 bytes; larger is suspicious

### Step 7: Extract Payloads

```
Extracting payloads for packets between 100-200 bytes...
Found 47 unique payloads
Saved: cleaned_unique_payloads.csv
```

Payloads are extracted, cleaned, deduplicated, and saved.

## Complete Example Session

```bash
$ ./packet-peeker -f suspicious_traffic.pcapng

=== go-packet-peeker ===

Loading capture file...
Parsing packets...

Found 12 unique source IPs:

1. 10.0.0.5
2. 10.0.0.10
3. 10.0.0.15
...

Select source IP (enter number): 2

Found 4 unique destination IPs for source 10.0.0.10:

1. 10.0.0.1
2. 192.168.1.1
3. 198.51.100.25
4. 203.0.113.100

Select destination IP (enter number): 3

Analyzing flow 10.0.0.10 → 198.51.100.25...

Protocols detected:

1. ICMPv4 (Type 08) - 500 packets
2. ICMPv4 (Type 00) - 500 packets
3. ICMPv4 (Type 03) - 127 packets

Select protocol (enter number): 3

Generating histogram for ICMPv4 (Type 03)...
Saved: result.png

Enter minimum packet size (bytes): 80
Enter maximum packet size (bytes): 150

Extracting payloads...
Found 127 packets in range
Extracted 45 unique payloads
Saved: cleaned_unique_payloads.csv

Analysis complete!
```

## Output Files

### result.png

The histogram visualizes packet size distribution:

```
┌────────────────────────────────────────────────────────┐
│     Packet Size Distribution                           │
│     Flow: 10.0.0.10 → 198.51.100.25                   │
│     Protocol: ICMPv4 (Type 03)                        │
│                                                        │
│  50 ┤          ████                                    │
│  40 ┤          ████ ████                               │
│  30 ┤     ████ ████ ████                               │
│  20 ┤████ ████ ████ ████ ████                          │
│  10 ┤████ ████ ████ ████ ████ ████                     │
│     └──────────────────────────────────────────►       │
│        48   64   80   96  112  128  144                │
│                   Packet Size (bytes)                  │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### cleaned_unique_payloads.csv

CSV file containing extracted payloads:

```csv
Cleaned Unique Payload
"AAAAAAAAAAAAAAAAAAAAAA=="
"Y21kLmV4ZSAvYyB3aG9hbWk="
"d2hvYW1p"
"hostname"
"ipconfig /all"
```

## Analyzing Results

### Reading the Histogram

1. **Normal ICMP**: Single narrow peak around 64 bytes
2. **Suspicious ICMP**: Multiple peaks or wide distribution
3. **Tunneling**: Bimodal distribution (small control + large data)

### Reading Payloads

Look for:
- Base64-encoded strings (data exfiltration)
- Command strings (`whoami`, `cmd.exe`, etc.)
- HTTP headers in non-HTTP protocols
- Repeated patterns indicating beaconing

### Common Patterns

| Payload Pattern | Possible Indication |
|-----------------|---------------------|
| Base64 strings | Encoded commands/data |
| HTTP verbs | Protocol tunneling |
| Shell commands | Remote execution |
| IP addresses | C2 configuration |
| Timestamps | Beaconing interval |

## Workflow Recommendations

### For ICMP Analysis

1. Filter for ICMP Type 3 (Destination Unreachable)
2. Check histogram for bimodal distribution
3. Extract payloads from larger-than-expected packets (>64 bytes)
4. Look for encoded data or command strings

### For DNS Analysis

1. Filter for DNS protocol
2. Check for large TXT record responses
3. Extract payloads from oversized packets (>512 bytes)
4. Look for base64 or hex-encoded data

### For General Analysis

1. Identify unusual flows (internal → external)
2. Check for asymmetric traffic patterns
3. Focus on protocols with unexpected payload sizes
4. Cross-reference with known C2 signatures

## Troubleshooting

### "No packets found"

- Verify PCAP file path is correct
- Check file format (PCAP or PCAPng)
- Ensure file is not corrupted

### "No protocols detected"

- Selected flow may not have matching packets
- Try different source/destination combination

### Histogram not generated

- Ensure write permissions in current directory
- Check disk space

### Empty payloads

- Packets may not have application layer data
- Size range may exclude all packets
- Protocol may not have extractable payloads

## Next Steps

- [Analysis Guide](analysis-guide.md) - Detecting covert channels
- [Architecture](architecture.md) - How the tool works
- [Configuration](configuration.md) - Advanced options

