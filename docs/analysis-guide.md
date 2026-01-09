# go-packet-peeker Analysis Guide

This guide covers detection techniques for covert channels and protocol anomalies.

## Covert Channel Overview

| Channel Type | Protocol | Detection Method |
|--------------|----------|------------------|
| ICMP Tunneling | ICMP | Size analysis, Type 3 abuse |
| DNS Tunneling | DNS | TXT record size, query frequency |
| HTTP Tunneling | HTTP | Header anomalies, encoding |
| Protocol Abuse | Various | Unexpected payload sizes |

## ICMP Tunneling Detection

### Normal ICMP Characteristics

| ICMP Type | Name | Expected Size |
|-----------|------|---------------|
| 0 | Echo Reply | 64-84 bytes |
| 3 | Destination Unreachable | 36-64 bytes |
| 8 | Echo Request | 64-84 bytes |
| 11 | Time Exceeded | 36-64 bytes |

### Suspicious Indicators

```
┌─────────────────────────────────────────────────────────────┐
│                    ICMP Size Histogram                       │
│                                                             │
│  Normal (single peak ~64 bytes):                            │
│                                                             │
│  100 ┤     ████                                              │
│   80 ┤     ████                                              │
│   60 ┤    █████                                              │
│   40 ┤   ██████                                              │
│   20 ┤  ████████                                             │
│      └────────────────────────────────────►                  │
│         32   64   96  128  160  192                         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Suspicious (bimodal - tunneling):                          │
│                                                             │
│  100 ┤     ████                ████                          │
│   80 ┤     ████               █████                          │
│   60 ┤    █████              ██████                          │
│   40 ┤   ██████             ████████                         │
│   20 ┤  ████████           ██████████                        │
│      └────────────────────────────────────►                  │
│         32   64   96  128  160  192  224  256               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### ICMP Type 3 Abuse

Type 3 (Destination Unreachable) is commonly abused:

**Why Type 3?**
- Appears as normal network errors
- Often not filtered by firewalls
- Less scrutinized than Echo Request/Reply
- Can carry arbitrary data in "original datagram" field

**Detection:**
1. Select ICMPv4 (Type 03) in protocol selection
2. Check histogram for sizes > 64 bytes
3. Extract payloads from oversized packets
4. Look for encoded data or command strings

### ICMP Analysis Workflow

```
1. Filter: ICMPv4 (Type 03)
                │
                ▼
2. Histogram Analysis
   • Single peak at 36-64 bytes → Normal
   • Multiple peaks or wide spread → Suspicious
                │
                ▼
3. Size Range Selection
   • Target packets > 64 bytes
   • Focus on secondary peak in bimodal
                │
                ▼
4. Payload Extraction
   • Look for base64 strings
   • Check for command patterns
   • Identify data exfiltration
```

### Example Payloads

**Normal ICMP Type 3:**
```
(Original IP header + 8 bytes of original datagram)
```

**Tunneled Data:**
```csv
"Y21kLmV4ZSAvYyB3aG9hbWk="    # cmd.exe /c whoami
"aXBjb25maWcgL2FsbA=="        # ipconfig /all
"bmV0IHVzZXI="                 # net user
```

## DNS Tunneling Detection

### Normal DNS Characteristics

| Record Type | Expected Size | Normal Use |
|-------------|---------------|------------|
| A | ~100 bytes | IP address lookup |
| AAAA | ~100 bytes | IPv6 lookup |
| TXT | Variable | SPF, DKIM, verification |
| MX | ~150 bytes | Mail server lookup |

### Suspicious Indicators

1. **Large TXT Responses** (> 512 bytes)
2. **High Query Frequency** (beaconing)
3. **Encoded Subdomains** (base64/hex)
4. **Unusual Query Patterns**

### DNS Analysis Workflow

```
1. Filter: DNS protocol
                │
                ▼
2. Histogram Analysis
   • Check for packets > 512 bytes
   • Look for consistent large responses
                │
                ▼
3. Payload Extraction
   • Focus on TXT record responses
   • Look for base64 in domain names
                │
                ▼
4. Pattern Analysis
   • Regular intervals = beaconing
   • Encoded data = data transfer
```

### Example DNS Tunnel Payloads

```csv
"aGVsbG8gd29ybGQ=.tunnel.example.com"
"ZGF0YQ==.exfil.attacker.com"
"Y29tbWFuZA==.c2.malicious.net"
```

## Protocol Abuse Detection

### Protocols Commonly Abused

| Protocol | Normal Use | Abuse Vector |
|----------|------------|--------------|
| ICMP | Network diagnostics | Data tunneling |
| DNS | Name resolution | Data exfiltration |
| NTP | Time sync | Amplification, tunneling |
| HTTP | Web traffic | C2 communication |

### Size Anomaly Detection

For any protocol, compare expected vs. observed sizes:

```
Expected Size Ranges:

Protocol     Min    Max    Suspicious If
─────────────────────────────────────────
ICMP Echo    64     84     > 100 bytes
ICMP Type 3  36     64     > 64 bytes
DNS Query    ~50    ~100   > 255 bytes
DNS Response ~100   ~512   > 512 bytes
NTP          48     68     > 100 bytes
```

## Payload Analysis Techniques

### Base64 Detection

Look for strings matching:
- Alphanumeric characters
- Ending with `=` or `==`
- Length divisible by 4

```csv
"SGVsbG8gV29ybGQ="        # Hello World
"Y21kLmV4ZSAvYyBkaXI="    # cmd.exe /c dir
```

### Command String Detection

Common patterns in payloads:

```
Windows Commands:
- cmd.exe, powershell
- whoami, ipconfig, net user
- dir, type, copy

Linux Commands:
- /bin/sh, /bin/bash
- id, whoami, uname
- ls, cat, wget, curl
```

### Hex-Encoded Data

Look for:
- Long strings of 0-9, a-f, A-F
- Even-length strings
- No spaces or special characters

```csv
"68656c6c6f"              # hello
"636d642e657865"          # cmd.exe
```

## Analysis Checklist

### Initial Triage

- [ ] Identify all unique flows in PCAP
- [ ] Note internal vs. external communications
- [ ] Flag unusual protocol usage

### ICMP Analysis

- [ ] Check for ICMP Type 3 packets
- [ ] Generate histogram for each ICMP type
- [ ] Look for bimodal distributions
- [ ] Extract payloads from oversized packets
- [ ] Decode base64/hex strings

### DNS Analysis

- [ ] Filter for DNS traffic
- [ ] Check response sizes
- [ ] Look for TXT record abuse
- [ ] Check for encoded subdomains
- [ ] Analyze query frequency

### General Analysis

- [ ] Compare packet sizes to expected norms
- [ ] Look for beaconing patterns (regular intervals)
- [ ] Cross-reference with known C2 signatures
- [ ] Document suspicious findings

## MITRE ATT&CK Mapping

| Technique | ID | go-packet-peeker Detection |
|-----------|-----|---------------------------|
| Protocol Tunneling | T1572 | Size histogram anomalies |
| Non-Application Layer Protocol | T1095 | ICMP payload extraction |
| Application Layer Protocol | T1071 | DNS/HTTP analysis |
| Data Encoding | T1132 | Base64 payload detection |
| Exfiltration Over C2 Channel | T1041 | Outbound payload analysis |

## Reporting Findings

### Document for Each Finding

1. **Flow**: Source IP → Destination IP
2. **Protocol**: Specific protocol and type
3. **Anomaly**: Size deviation, payload content
4. **Evidence**: Histogram screenshot, payload samples
5. **Assessment**: Confidence level (Low/Medium/High)

### Example Finding Report

```
FINDING: ICMP Tunneling Detected

Flow: 10.0.0.50 → 203.0.113.100
Protocol: ICMPv4 (Type 03)
Time Range: 2024-01-15 14:00:00 - 14:30:00

Observations:
- 127 ICMP Type 3 packets in 30-minute window
- Bimodal size distribution (64 bytes + 128-200 bytes)
- Payloads contain base64-encoded commands

Sample Payloads:
- "Y21kLmV4ZSAvYyBpcGNvbmZpZw==" → cmd.exe /c ipconfig
- "d2hvYW1p" → whoami

Assessment: HIGH confidence covert channel

Recommendation: Block ICMP traffic to 203.0.113.100
                Investigate host 10.0.0.50 for compromise
```

## Integration with Other Tools

### Export for Further Analysis

```bash
# Extract suspicious IPs
grep -E "^[0-9]" cleaned_unique_payloads.csv | sort -u

# Decode base64 payloads
cat cleaned_unique_payloads.csv | base64 -d 2>/dev/null

# Feed to threat intel
# (integrate with your SIEM/SOAR platform)
```

### Complementary Tools

| Tool | Use Case |
|------|----------|
| Wireshark | Deep packet inspection |
| Zeek | Flow analysis, scripting |
| tcpdump | Packet filtering |
| tshark | Command-line analysis |

## Next Steps

- [Usage Guide](usage-guide.md) - Interactive workflow
- [Architecture](architecture.md) - How the tool works
- [Configuration](configuration.md) - Options reference

