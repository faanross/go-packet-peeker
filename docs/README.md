# go-packet-peeker Documentation

Technical documentation for go-packet-peeker, a PCAP analysis tool for detecting covert channels and protocol abuse.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System design and data flow |
| [Usage Guide](usage-guide.md) | Interactive workflow walkthrough |
| [Analysis Guide](analysis-guide.md) | Detecting covert channels and anomalies |
| [Configuration](configuration.md) | Command-line options and customization |

## Quick Reference

### Installation

```bash
git clone https://github.com/faanross/go-packet-peeker.git
cd go-packet-peeker
go build -o packet-peeker ./cmd/main.go
```

### Basic Usage

```bash
./packet-peeker -f capture.pcapng
```

### Output Files

| File | Contents |
|------|----------|
| `result.png` | Packet size histogram |
| `cleaned_unique_payloads.csv` | Extracted unique payloads |

## Tool Purpose

go-packet-peeker helps analysts identify:

1. **ICMP Tunneling** - Data hidden in ICMP echo/reply or error messages
2. **Protocol Abuse** - Oversized DNS, NTP, or control packets
3. **Covert Channels** - Unexpected payload size variations
4. **Data Exfiltration** - Unusual payload patterns indicating smuggled data

## Workflow Overview

```
Load PCAP → Select Flow → Choose Protocol → Set Size Range → Analyze
     ↓           ↓              ↓                ↓             ↓
   Parse     Source IP     Detected        Min/Max       Histogram
   Packets   Dest IP       Protocols       Bytes         + Payloads
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| gopacket | v1.1.19 | Packet parsing |
| gonum/plot | v0.16.0 | Histogram generation |

## Related Reading

- [Main README](../README.md) - Project overview and examples
- [Sample PCAP](../sample/) - Test captures for practice

