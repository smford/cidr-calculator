# cidr-calculator

[![CI](https://github.com/smford/cidr-calculator/actions/workflows/ci.yml/badge.svg)](https://github.com/smford/cidr-calculator/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/smford/cidr-calculator)](https://goreportcard.com/report/github.com/smford/cidr-calculator)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance, zero-dependency Go terminal tool and library designed for Site Reliability Engineers, cloud architects, network engineers, and systems developers. `cidr-calculator` converts arbitrary IPv4 and IPv6 address ranges into minimal Classless Inter-Domain Routing (CIDR) blocks, aggregates subnets, detects collisions and containment, carves out exclusions, plans subnet allocations, and formats directly for Terraform, AWS, and CSV.

---

## Features

- **Minimal CIDR Decomposition**: Decomposes any IPv4 or IPv6 range into the smallest possible set of valid non-overlapping CIDR blocks.
- **Dual-Stack IPv4 & IPv6**: First-class 128-bit IPv6 range math and CIDR decomposition alongside full IPv4 capabilities.
- **CIDR Aggregation (`aggregate`)**: Merges overlapping and contiguous CIDR blocks into their minimal superset (e.g., combining adjacent `/24`s into `/23`s or `/22`s).
- **Collision & Overlap Detection (`overlap`)**: Identifies address collisions between subnets and calculates exact intersection intervals. Returns exit code `1` on collision, making it an ideal CI/CD pipeline blocker.
- **Range Containment (`contains`)**: Evaluates whether a VPC or supernet completely encloses a target subnet or host IP. Returns exit code `0` (true) or `1` (false).
- **Subnet Carving / Exclusion (`exclude`)**: Subtracts gateway, DHCP, or reserved address ranges from a parent network, returning the remaining optimal CIDR blocks.
- **Subnet Capacity Planner (`split`)**: Subdivides parent CIDRs into smaller subnets either by prefix length (e.g., `/24`) or by target subnet count (e.g., `4`).
- **IaC & Automation Formats (`-format=...`)**:
  - `terraform` (or `tf`): Direct HCL list format `["10.0.0.0/24", "10.0.1.0/24"]`
  - `aws`: AWS Security Group Ingress JSON array with CIDRs and descriptions
  - `csv`: Spreadsheet table (`cidr,start_ip,end_ip,count`)
  - `json`: Compact JSON array or structured diagnostic object (`-json`)
- **IPv4 Address Conversion (`convert`)**: Converts IPv4 addresses seamlessly between Integer (decimal), Hexadecimal (`0x...`), Binary (dotted quad or 32-bit plain), and Dotted Decimal formats.
- **Flexible Range Inputs**:
  - Plus offset notation: `192.168.1.10+5` or `192.168.1.10 + 5`
  - Hyphenated: `192.168.1.10-192.168.1.20` or `192.168.1.10 - 192.168.1.20`
  - Two arguments: `192.168.1.10 192.168.1.20`
  - Double dot: `192.168.1.10..192.168.1.20`
  - Shorthand last-octet: `10.0.0.1-50`
  - CIDR notation: `10.0.0.0/24` or `2001:db8::/32`
  - Single IP: `192.168.1.1` (outputs `/32`) or `2001:db8::1` (outputs `/128`)
  - Standard input (pipeline/file streaming): `cat ranges.txt | cidr-calculator`
- **Output Control**:
  - `all`: Prints both the CIDR blocks and all individual IP addresses.
  - `nocidr`: Suppresses CIDR output and prints *only* individual IP addresses.
  - `info`: Detailed diagnostic, architectural, RFC classification, and bitmask analysis.
- **Shell Autocompletion (`completion`)**: Built-in autocompletion generator for Bash, Zsh, and Fish.
- **Packaging & Portability**: Scratch-based Docker container, GoReleaser multi-arch binaries, and zero external dependencies.

---

## Installation

### Via Homebrew (macOS & Linux)

```bash
brew install smford/tap/cidr-calculator
```

### Via `go install` (Go 1.22+)

```bash
go install github.com/smford/cidr-calculator@latest
```

### From Source

```bash
git clone https://github.com/smford/cidr-calculator.git
cd cidr-calculator
make build
# Binary created at ./cidr-calculator
```

To install system-wide (to `$GOPATH/bin`):

```bash
make install
```

### Via Docker

Run directly using Docker (static scratch image, non-root user):

```bash
docker run --rm ghcr.io/smford/cidr-calculator:latest 192.168.1.10+5
```

Or build locally:

```bash
make docker-build
docker run --rm cidr-calculator:latest 192.168.1.10+5
```

---

## Shell Autocompletion

Enable tab autocompletion for subcommands, flags, and format presets:

### Bash

```bash
source <(cidr-calculator completion bash)
```

To persist in your shell profile:

```bash
cidr-calculator completion bash > /etc/bash_completion.d/cidr-calculator
```

### Zsh

```bash
source <(cidr-calculator completion zsh)
```

### Fish

```bash
cidr-calculator completion fish | source
```

---

## Usage Guide

### 1. Plus Offset Notation (`IP+count`)

Provide a base IP and host count (e.g., `192.168.1.10+5` covers `192.168.1.10` through `192.168.1.15`):

```bash
$ cidr-calculator 192.168.1.10+5
192.168.1.10/31
192.168.1.12/30
```

### 2. Print All IP Addresses (`all`)

Outputs the minimal CIDR blocks followed by every individual IP address:

```bash
$ cidr-calculator 192.168.1.10+5 all
192.168.1.10/31
192.168.1.12/30
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
192.168.1.15
```

### 3. Print Only IP Addresses (`nocidr`)

Suppresses CIDR blocks and streams *only* the individual IP addresses:

```bash
$ cidr-calculator 192.168.1.10+5 nocidr
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
192.168.1.15
```

### 4. IaC Output Presets (`-format=...`)

Directly output subnets formatted for infrastructure pipelines:

```bash
# Terraform / OpenTofu HCL list:
$ cidr-calculator -format=terraform 192.168.1.10+5
["192.168.1.10/31", "192.168.1.12/30"]

# AWS Security Group Ingress rules JSON:
$ cidr-calculator -format=aws 192.168.1.10+5
[
  {
    "CidrIp": "192.168.1.10/31",
    "Description": "Managed by cidr-calculator"
  },
  {
    "CidrIp": "192.168.1.12/30",
    "Description": "Managed by cidr-calculator"
  }
]

# CSV spreadsheet export:
$ cidr-calculator -format=csv 10.0.0.0/22
cidr,start_ip,end_ip,count
10.0.0.0/22,10.0.0.0,10.0.3.255,1024
```

### 5. CIDR Aggregation & Route Summarization (`aggregate`)

Combine fragmented, adjacent, or overlapping CIDRs into their minimal superset:

```bash
$ cidr-calculator aggregate 10.0.0.0/24 10.0.1.0/24 10.0.0.128/25
10.0.0.0/23

# Aggregate directly into Terraform format:
$ cidr-calculator -format=terraform aggregate 192.168.0.0/24 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24
["192.168.0.0/22"]
```

### 6. Subnet Collision & Overlap Detection (`overlap`)

Check if two IP ranges or subnets intersect. In CI/CD pipelines, this command exits with code `1` when an overlap is detected and `0` when clean:

```bash
# Overlap detected (exits with code 1):
$ cidr-calculator overlap 10.100.0.0/16 10.100.32.0/20
OVERLAP DETECTED: 10.100.0.0/16 overlaps with 10.100.32.0/20
Intersection:     10.100.32.0 - 10.100.47.255
CIDR Blocks:
  10.100.32.0/20
$ echo $?
1

# Clean subnets (exits with code 0):
$ cidr-calculator overlap 10.0.0.0/24 10.0.1.0/24
NO OVERLAP: 10.0.0.0/24 does not overlap with 10.0.1.0/24
$ echo $?
0
```

### 7. Containment Check (`contains`)

Verify whether a parent VPC or supernet encloses a target IP or subnet. Exits with code `0` on true and `1` on false:

```bash
$ cidr-calculator contains 10.0.0.0/16 10.0.5.1
YES: 10.0.0.0/16 contains 10.0.5.1
$ echo $?
0

$ cidr-calculator contains 10.0.0.0/16 192.168.1.1
NO: 10.0.0.0/16 does not contain 192.168.1.1
$ echo $?
1
```

### 8. Subnet Carving / Exclusion (`exclude`)

Subtract reserved IP ranges (e.g., gateway IPs, DHCP pools) from a base subnet:

```bash
# Exclude gateway IP .1 and DHCP pool .100-.150 from 192.168.1.0/24:
$ cidr-calculator exclude 192.168.1.0/24 192.168.1.1 192.168.1.100-192.168.1.150
192.168.1.0/32
192.168.1.2/31
192.168.1.4/30
192.168.1.8/29
192.168.1.16/28
192.168.1.32/27
192.168.1.64/27
192.168.1.96/30
192.168.1.151/32
192.168.1.152/29
192.168.1.160/27
192.168.1.192/26
```

### 9. Subnet Capacity Planner (`split`)

Subdivide parent CIDRs into smaller subnets by prefix length or target count:

```bash
# Split /22 into /24 subnets:
$ cidr-calculator split 10.0.0.0/22 /24
10.0.0.0/24
10.0.1.0/24
10.0.2.0/24
10.0.3.0/24

# Split /22 into 4 equal subnets:
$ cidr-calculator split 10.0.0.0/22 4
10.0.0.0/24
10.0.1.0/24
10.0.2.0/24
10.0.3.0/24
```

### 10. IPv4 Format Conversion (`convert`)

Convert an IPv4 address between **Integer**, **Hexadecimal**, **Binary**, and **Dotted Decimal** formats:

```bash
# Convert decimal integer:
$ cidr-calculator convert 3232235786
Input:          3232235786 (Integer)
IPv4 Address:   192.168.1.10
Hexadecimal:    0xC0A8010A
Binary:         11000000.10101000.00000001.00001010
Binary (Plain): 11000000101010000000000100001010

# Convert hexadecimal:
$ cidr-calculator convert 0xC0A8010A
Input:          0xC0A8010A (Hexadecimal)
IPv4 Address:   192.168.1.10
Integer:        3232235786
Binary:         11000000.10101000.00000001.00001010
Binary (Plain): 11000000101010000000000100001010

# Machine-readable JSON output:
$ cidr-calculator -json convert 3232235786
{
  "input": "3232235786",
  "input_type": "Integer",
  "ipv4": "192.168.1.10",
  "integer": 3232235786,
  "hex": "0xC0A8010A",
  "binary": "11000000.10101000.00000001.00001010",
  "binary_plain": "11000000101010000000000100001010"
}
```

### 11. Detailed Diagnostic & RFC Intelligence (`info`)

Outputs in-depth network and architectural diagnostics with ANSI colorized bitmasks (network bits vs. host bits) when running interactively in a TTY:

```bash
$ cidr-calculator 192.168.1.10+5 info
================================================================================
IP Range Analysis & Details
================================================================================
Range:             192.168.1.10+5
Total Addresses:   6
CIDR Block(s):     2
Scope:             Private-Use / Internal (RFC 1918)
Historical Class:  Class C (Historical /24)

Start Address:
  IP:              192.168.1.10
  Integer:         3232235786
  Hex:             0xC0A8010A
  Binary:          11000000.10101000.00000001.00001010

End Address:
  IP:              192.168.1.15
  Integer:         3232235791
  Hex:             0xC0A8010F
  Binary:          11000000.10101000.00000001.00001111

CIDR Decomposition:
  [1] 192.168.1.10/31
      Range:         192.168.1.10 - 192.168.1.11 (2 address(es))
      Netmask:       255.255.255.254
      Wildcard:      0.0.0.1
  [2] 192.168.1.12/30
      Range:         192.168.1.12 - 192.168.1.15 (4 address(es))
      Netmask:       255.255.255.252
      Wildcard:      0.0.0.3
================================================================================
```

### 12. Standard Input (Pipelines & Batch Files)

Stream lists of IP ranges directly via `stdin` (comments `#` and blank lines are ignored):

```bash
$ cat ranges.txt
# Production Web Tier
192.168.1.10+5
# Database Cluster
10.0.0.1 - 10.0.0.6

$ cat ranges.txt | cidr-calculator
192.168.1.10/31
192.168.1.12/30
10.0.0.1/32
10.0.0.2/31
10.0.0.4/31
10.0.0.6/32
```

---

## Subcommands & Options Reference

### Subcommands

| Subcommand | Description |
| :--- | :--- |
| `convert <input>` | Convert an IPv4 address between integer, hex, binary, and dotted decimal |
| `aggregate <ranges...>` | Merge adjacent and overlapping CIDR blocks into minimal supersets |
| `overlap <range1> <range2>` | Detect collisions between two ranges (exits with code 1 on collision) |
| `contains <parent> <target>` | Check if a parent range completely encloses a target IP or range |
| `exclude <base> <exclusions...>` | Subtract excluded IP ranges from a base range |
| `split <cidr> <prefix\|count>` | Subdivide parent CIDR into smaller subnets |
| `completion <shell>` | Generate shell autocompletion script (`bash`, `zsh`, `fish`) |

### Arguments & Options

| Option / Flag | Description |
| :--- | :--- |
| `all`, `-all` | Print out a list of all IP addresses in the range |
| `nocidr`, `-nocidr` | Suppress CIDR output and only print the list of IP addresses |
| `info`, `-info` | Print detailed diagnostic, RFC scope, and subnet analysis |
| `-format=...` | Output preset: `cidr` (default), `terraform` (or `tf`), `aws`, `csv`, `json` |
| `-json` | Output results in structured JSON format |
| `-s`, `-summary` | Display summary statistics (total IPs and CIDR block count) |
| `-v`, `-version` | Display version, git commit, and build date |
| `-h`, `-help` | Display help and usage information |

---

## Go Library Usage

The calculation and manipulation engine is packaged cleanly under `pkg/cidr` and can be imported into any Go application:

```go
package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func main() {
	start := netip.MustParseAddr("192.168.1.10")
	end := netip.MustParseAddr("192.168.1.15")

	// Minimal CIDR decomposition
	prefixes, err := cidr.RangeToCIDRs(start, end)
	if err != nil {
		log.Fatalf("conversion failed: %v", err)
	}
	for _, p := range prefixes {
		fmt.Println("CIDR:", p)
	}

	// Stream individual IP addresses
	_ = cidr.GenerateIPs(start, end, func(ip netip.Addr) bool {
		fmt.Println("IP:", ip)
		return true
	})

	// Subnet overlap detection
	r1, _ := cidr.ParseRange("10.0.0.0/16")
	r2, _ := cidr.ParseRange("10.0.5.0/24")
	overlap, _ := cidr.CheckOverlap(r1, r2)
	fmt.Printf("Overlaps: %v, Intersection: %s\n", overlap.Overlaps, overlap.Intersection.Raw)

	// Format for Terraform
	tfOutput, _ := cidr.FormatPrefixes(prefixes, cidr.FormatTerraform)
	fmt.Println("Terraform:", tfOutput)
}
```

---

## Development & Verification

```bash
# Run tests with race condition detector
make test-race

# Run benchmarks
make bench

# Check test coverage
make cover

# Format and lint code
make fmt
make lint

# Build Docker image
make docker-build
```

### Benchmark Results (Apple Silicon M4)

```text
BenchmarkRangeToCIDRs_Small-10    18264352    58.37 ns/op     224 B/op    3 allocs/op
BenchmarkRangeToCIDRs_Large-10     2519394   471.60 ns/op    4448 B/op    7 allocs/op
BenchmarkParseRange-10            10866890   111.10 ns/op       0 B/op    0 allocs/op
BenchmarkConvertIP-10              3811416   313.00 ns/op     112 B/op    5 allocs/op
```

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).