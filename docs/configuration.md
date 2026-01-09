# go-packet-peeker Configuration

Complete reference for command-line options and customization.

## Command-Line Options

### Required Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-f` | Path to PCAP/PCAPng file | `-f capture.pcapng` |

### Usage

```bash
./packet-peeker -f /path/to/capture.pcapng
```

## Interactive Configuration

The tool uses interactive prompts for analysis parameters.

### Source IP Selection

```
Found N unique source IPs:

1. 10.0.0.1
2. 192.168.1.100
...

Select source IP (enter number): _
```

Enter the number corresponding to your chosen source IP.

### Destination IP Selection

```
Found N unique destination IPs for source X.X.X.X:

1. 10.0.0.1
2. 203.0.113.50
...

Select destination IP (enter number): _
```

Enter the number corresponding to your chosen destination IP.

### Protocol Selection

```
Protocols detected in flow:

1. ICMPv4 (Type 08) - 500 packets
2. ICMPv4 (Type 00) - 500 packets
3. TCP - 100 packets

Select protocol (enter number): _
```

Enter the number for the protocol to analyze.

### Size Range

```
Enter minimum packet size (bytes): _
Enter maximum packet size (bytes): _
```

Specify the byte range for payload extraction.

## Hardcoded Configuration

### Histogram Settings

Located in `cmd/main.go`:

```go
const defaultHistogramBins = 50
```

| Setting | Value | Description |
|---------|-------|-------------|
| Bins | 50 | Number of histogram bins |
| Width | 12 inches | Plot width |
| Height | 9 inches | Plot height |
| Bar Color | RGB(255,153,0) | Orange bars |

### Output Files

| File | Location | Format |
|------|----------|--------|
| Histogram | `./result.png` | PNG image |
| Payloads | `./cleaned_unique_payloads.csv` | CSV |

Files are written to the current working directory.

## Supported Protocols

### Detection Priority

The tool detects protocols in this order:

| Priority | Protocol | Detection Method |
|----------|----------|------------------|
| 1 | DNS | Layer type |
| 2 | HTTP | Payload signature |
| 3 | TLS | Layer type |
| 4 | TCP (80/443) | Port detection |
| 5 | UDP (53) | Port detection |
| 6 | TCP | Layer type |
| 7 | UDP | Layer type |
| 8 | ICMPv4 | Layer type + type code |
| 9 | ICMPv6 | Layer type + type code |
| 10 | IPv4/IPv6 | Network layer |
| 11 | Other | Fallback |

### HTTP Signature Detection

```go
signatures := []string{
    "HTTP/",
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "HEAD ",
}
```

## Payload Cleaning

### ASCII Filter

Characters preserved:
- Printable ASCII: 32-126 (space through tilde)
- Tab: 9 (`\t`)
- Newline: 10 (`\n`)
- Carriage return: 13 (`\r`)

All other bytes are replaced with `.`

### Prefix Cleaning

Sequences of 5 or more consecutive dots are removed along with preceding content:

```
Before: "....................................................Hello World"
After:  "Hello World"
```

## Build Configuration

### Standard Build

```bash
go build -o packet-peeker ./cmd/main.go
```

### Optimized Build

```bash
# Strip debug symbols (smaller binary)
go build -ldflags="-s -w" -o packet-peeker ./cmd/main.go
```

### Cross-Compilation

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o packet-peeker.exe ./cmd/main.go

# Linux
GOOS=linux GOARCH=amd64 go build -o packet-peeker ./cmd/main.go

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o packet-peeker_mac ./cmd/main.go

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o packet-peeker_mac_arm ./cmd/main.go
```

## Dependencies

### Direct Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| gopacket | v1.1.19 | Packet parsing |
| gonum/plot | v0.16.0 | Histogram generation |

### Installing Dependencies

```bash
go mod download
```

### Updating Dependencies

```bash
go get -u ./...
go mod tidy
```

## File Format Support

### PCAP

- Legacy format
- Single interface
- Extension: `.pcap`

### PCAPng

- Modern format (recommended)
- Multiple interfaces
- Metadata support
- Extension: `.pcapng`

Both formats are automatically detected by gopacket.

## Performance Tuning

### Large PCAP Files

For captures > 1GB:

1. **Pre-filter** using tcpdump or tshark:
   ```bash
   tcpdump -r large.pcap -w filtered.pcap 'icmp'
   ```

2. **Split by time** if needed:
   ```bash
   editcap -i 300 large.pcap split.pcap  # 5-minute splits
   ```

### Memory Usage

The tool stores:
- IP addresses (minimal)
- Packet sizes (per-flow)
- Payloads (for extraction)

Memory scales with unique payloads, not total packets.

## Customization

### Modifying Histogram Bins

Edit `cmd/main.go`:

```go
const defaultHistogramBins = 100  // Increase for finer granularity
```

### Changing Output Filenames

Edit the file writing sections in `cmd/main.go`:

```go
// Histogram
plot.Save(12*vg.Inch, 9*vg.Inch, "custom_histogram.png")

// Payloads
file, _ := os.Create("custom_payloads.csv")
```

### Adding Protocol Detection

Add cases to `getPacketProtocol()`:

```go
// Example: Detect MQTT
if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
    tcpLayer, _ := tcp.(*layers.TCP)
    if tcpLayer.DstPort == 1883 || tcpLayer.SrcPort == 1883 {
        return "MQTT"
    }
}
```

## Troubleshooting

### "Error opening PCAP file"

- Verify file exists and path is correct
- Check file permissions
- Ensure file is not corrupted

### "No packets found"

- File may be empty
- Check capture filter used during recording

### "Permission denied" on output

- Verify write access to current directory
- Check disk space

### Histogram not generated

- gonum/plot may require additional graphics libraries
- On Linux: `apt install libpng-dev libjpeg-dev`

## Example Configurations

### Basic Analysis

```bash
./packet-peeker -f traffic.pcapng
# Follow interactive prompts
```

### Scripted Analysis (Future)

Currently interactive only. For automation, consider:
1. Pre-filtering with tshark
2. Custom scripts using gopacket library

## Directory Structure

```
go-packet-peeker/
├── cmd/
│   └── main.go           # Main application
├── docs/
│   ├── README.md
│   ├── architecture.md
│   ├── usage-guide.md
│   ├── analysis-guide.md
│   └── configuration.md
├── sample/               # Test PCAP files
├── img/                  # README images
├── go.mod
├── go.sum
└── README.md
```

## Next Steps

- [Usage Guide](usage-guide.md) - Interactive workflow
- [Analysis Guide](analysis-guide.md) - Detection techniques
- [Architecture](architecture.md) - System design

