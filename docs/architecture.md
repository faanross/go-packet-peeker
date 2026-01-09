# go-packet-peeker Architecture

This document describes the system architecture and processing flow.

## Overview

go-packet-peeker is a single-file CLI tool that performs multi-pass analysis on PCAP files to identify covert channels and protocol anomalies.

## Design Philosophy

| Principle | Implementation |
|-----------|----------------|
| Simplicity | Single `main.go` file (~473 lines) |
| Interactivity | Step-by-step user prompts |
| Focus | Flow-based analysis, not full capture |
| Visualization | Histogram for pattern recognition |

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ANALYST WORKSTATION                             │
│                                                                             │
│    ┌──────────────┐         ┌──────────────────────────────────────────┐   │
│    │  PCAP File   │         │            go-packet-peeker               │   │
│    │              │         │                                           │   │
│    │  capture.    │────────►│  ┌────────────────────────────────────┐   │   │
│    │  pcapng      │         │  │           Four-Pass Engine          │   │   │
│    │              │         │  │                                      │   │   │
│    └──────────────┘         │  │  Pass 1: IP Enumeration             │   │   │
│                             │  │  Pass 2: Protocol Detection          │   │   │
│                             │  │  Pass 3: Size Histogram              │   │   │
│                             │  │  Pass 4: Payload Extraction          │   │   │
│                             │  │                                      │   │   │
│                             │  └────────────────────────────────────┘   │   │
│                             │                    │                      │   │
│                             │                    ▼                      │   │
│                             │  ┌────────────────────────────────────┐   │   │
│                             │  │           Output Generation         │   │   │
│                             │  │                                      │   │   │
│                             │  │  • result.png (histogram)           │   │   │
│                             │  │  • cleaned_unique_payloads.csv      │   │   │
│                             │  │                                      │   │   │
│                             │  └────────────────────────────────────┘   │   │
│                             │                                           │   │
│                             └──────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Processing Passes

### Pass 1: IP Enumeration

```
PCAP File
    │
    ▼
┌────────────────────┐
│  For each packet:  │
│  • Extract Src IP  │
│  • Extract Dst IP  │
│  • Store in sets   │
└────────────────────┘
    │
    ▼
┌────────────────────┐
│  Display unique    │
│  IPs with numbers  │
│  for selection     │
└────────────────────┘
```

**Output:** Numbered list of all unique source and destination IPs

### Pass 2: Protocol Detection

```
Selected Flow (Src → Dst)
    │
    ▼
┌────────────────────┐
│  For each packet   │
│  in flow:          │
│  • Check layers    │
│  • Identify proto  │
│  • Count packets   │
└────────────────────┘
    │
    ▼
┌────────────────────┐
│  Protocol summary  │
│  with counts       │
└────────────────────┘
```

**Detection Logic:**

```go
// Protocol detection order
1. DNS layer present        → "DNS"
2. HTTP signature in payload → "HTTP"
3. TLS layer present        → "TLS"
4. TCP layer (port 80/443)  → "HTTP" / "HTTPS"
5. UDP layer (port 53)      → "DNS"
6. TCP layer                → "TCP"
7. UDP layer                → "UDP"
8. ICMPv4 layer            → "ICMPv4 (Type XX)"
9. ICMPv6 layer            → "ICMPv6 (Type XX)"
10. IPv4/IPv6 layer        → "IP (Other)"
11. Fallback               → "Other"
```

### Pass 3: Histogram Generation

```
Selected Protocol
    │
    ▼
┌────────────────────┐
│  Collect packet    │
│  sizes for all     │
│  matching packets  │
└────────────────────┘
    │
    ▼
┌────────────────────┐
│  Generate PNG      │
│  histogram using   │
│  gonum/plot        │
└────────────────────┘
    │
    ▼
result.png
```

**Histogram Specifications:**

| Property | Value |
|----------|-------|
| Dimensions | 12" × 9" |
| Bins | 50 (default) |
| Bar Color | Orange (RGB: 255, 153, 0) |
| X-axis | Packet size (bytes) |
| Y-axis | Packet count |

### Pass 4: Payload Extraction

```
User Size Range (min-max)
    │
    ▼
┌────────────────────┐
│  For packets in    │
│  size range:       │
│  • Extract payload │
│  • Clean ASCII     │
│  • Deduplicate     │
└────────────────────┘
    │
    ▼
cleaned_unique_payloads.csv
```

**Payload Cleaning Pipeline:**

```
Raw Payload
    │
    ▼
┌────────────────────┐
│  ASCII Filter      │
│  Keep: 32-126      │
│  Plus: \n \r \t    │
│  Replace: → '.'    │
└────────────────────┘
    │
    ▼
┌────────────────────┐
│  Prefix Removal    │
│  Strip 5+ dots     │
│  and preceding     │
└────────────────────┘
    │
    ▼
┌────────────────────┐
│  Deduplication     │
│  & Sorting         │
└────────────────────┘
    │
    ▼
Cleaned Payload
```

## Code Structure

```
go-packet-peeker/
├── cmd/
│   └── main.go                 # Single-file application
│       │
│       ├── main()              # Entry point, orchestrates workflow
│       │
│       ├── getPacketProtocol() # Protocol identification
│       ├── cleanPayload()      # ASCII filtering
│       ├── cleanPrefix()       # Dot sequence removal
│       ├── getUserInput()      # Console prompts
│       ├── sortedKeys()        # Map key sorting
│       ├── sortedKeysInt()     # Int key sorting
│       └── generateHistogram() # PNG generation
│
├── go.mod                      # Module definition
├── go.sum                      # Dependencies
├── sample/                     # Test PCAP files
└── img/                        # README images
```

## Data Flow

### Complete Analysis Flow

```
                                    User Input
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌────────┐ │
│  │  PCAP   │───►│  Pass   │───►│  Pass   │───►│  Pass   │───►│ Pass   │ │
│  │  File   │    │    1    │    │    2    │    │    3    │    │   4    │ │
│  │         │    │         │    │         │    │         │    │        │ │
│  │         │    │   IP    │    │Protocol │    │Histogram│    │Payload │ │
│  │         │    │  Enum   │    │Detection│    │  Gen    │    │Extract │ │
│  └─────────┘    └────┬────┘    └────┬────┘    └────┬────┘    └───┬────┘ │
│                      │              │              │             │      │
│                      ▼              ▼              ▼             ▼      │
│                 ┌────────┐    ┌────────┐    ┌──────────┐  ┌──────────┐  │
│                 │ Select │    │ Select │    │result.png│  │payloads  │  │
│                 │Src/Dst │    │Protocol│    │          │  │   .csv   │  │
│                 └────────┘    └────────┘    └──────────┘  └──────────┘  │
│                      │              │                                   │
│                      └──────┬───────┘                                   │
│                             │                                           │
│                        Size Range                                       │
│                         Selection                                       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Supported Protocols

### Layer Detection

| Layer | Protocols | Detection Method |
|-------|-----------|------------------|
| Application | DNS, HTTP, TLS | Layer type or signature |
| Transport | TCP, UDP | Layer type |
| Network | ICMPv4, ICMPv6, IPv4, IPv6 | Layer type |

### ICMP Analysis

ICMP packets receive special treatment:

```go
// ICMP type reporting
"ICMPv4 (Type 03)"  // Destination Unreachable
"ICMPv4 (Type 08)"  // Echo Request
"ICMPv4 (Type 00)"  // Echo Reply
"ICMPv6 (Type 128)" // Echo Request
"ICMPv6 (Type 129)" // Echo Reply
```

This helps identify ICMP tunneling where Type 3 packets vary in size.

## Output Formats

### Histogram (result.png)

```
     Packet Count
           │
       100 ┤     ████
        80 ┤     ████ ████
        60 ┤████ ████ ████
        40 ┤████ ████ ████ ████
        20 ┤████ ████ ████ ████ ████
           └─────────────────────────────►
              64   128  256  512  1024
                   Packet Size (bytes)
```

### Payload CSV

```csv
Cleaned Unique Payload
"Base64EncodedString=="
"GET /api/beacon HTTP/1.1"
"cmd.exe /c whoami"
```

## Performance Characteristics

| PCAP Size | Processing Time | Memory Usage |
|-----------|-----------------|--------------|
| 1 MB | < 1 second | ~50 MB |
| 100 MB | ~10 seconds | ~200 MB |
| 1 GB | ~2 minutes | ~500 MB |

## Next Steps

- [Usage Guide](usage-guide.md) - Interactive workflow
- [Analysis Guide](analysis-guide.md) - Detecting anomalies
- [Configuration](configuration.md) - Options reference

