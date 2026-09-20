package cidr

import (
	"fmt"
	"net/netip"
	"strings"
)

// CIDRDetail encapsulates network metadata for an individual CIDR block.
type CIDRDetail struct {
	CIDR         string `json:"cidr"`
	Netmask      string `json:"netmask"`
	WildcardMask string `json:"wildcard_mask"`
	IPCount      uint64 `json:"ip_count"`
	StartIP      string `json:"start_ip"`
	EndIP        string `json:"end_ip"`
}

// RangeInfo encapsulates detailed diagnostic, classification, and architectural information
// for an IPv4 address range.
type RangeInfo struct {
	Range            string       `json:"range"`
	StartIP          string       `json:"start_ip"`
	EndIP            string       `json:"end_ip"`
	StartInteger     uint32       `json:"start_integer"`
	EndInteger       uint32       `json:"end_integer"`
	StartHex         string       `json:"start_hex"`
	EndHex           string       `json:"end_hex"`
	StartBinary      string       `json:"start_binary"`
	EndBinary        string       `json:"end_binary"`
	TotalIPs         uint64       `json:"total_ips"`
	CIDRCount        int          `json:"cidr_count"`
	Scope            string       `json:"scope"`
	HistoricalClass  string       `json:"historical_class"`
	IsSingleSubnet   bool         `json:"is_single_subnet"`
	NetworkIP        string       `json:"network_ip,omitempty"`
	BroadcastIP      string       `json:"broadcast_ip,omitempty"`
	Netmask          string       `json:"netmask,omitempty"`
	WildcardMask     string       `json:"wildcard_mask,omitempty"`
	UsableHostRange  string       `json:"usable_host_range,omitempty"`
	UsableHostsCount uint64       `json:"usable_hosts_count,omitempty"`
	CIDRs            []CIDRDetail `json:"cidrs"`
}

// GetRangeInfo analyzes an IPRange and produces comprehensive RangeInfo.
func GetRangeInfo(r IPRange) (RangeInfo, error) {
	prefixes, err := RangeToCIDRs(r.Start, r.End)
	if err != nil {
		return RangeInfo{}, err
	}

	totalIPs, err := TotalIPs(r.Start, r.End)
	if err != nil {
		return RangeInfo{}, err
	}

	startU, err := IPv4ToUint32(r.Start)
	if err != nil {
		return RangeInfo{}, err
	}
	endU, err := IPv4ToUint32(r.End)
	if err != nil {
		return RangeInfo{}, err
	}

	startScope := GetIPScope(r.Start)
	endScope := GetIPScope(r.End)
	scope := startScope
	if startScope != endScope {
		scope = fmt.Sprintf("Mixed (%s to %s)", startScope, endScope)
	}

	startClass := GetHistoricalClass(r.Start)
	endClass := GetHistoricalClass(r.End)
	historicalClass := startClass
	if startClass != endClass {
		historicalClass = fmt.Sprintf("Mixed (%s to %s)", startClass, endClass)
	}

	cidrDetails := make([]CIDRDetail, len(prefixes))
	for i, p := range prefixes {
		mask := PrefixMask(p.Bits())
		wildcard := PrefixWildcard(p.Bits())
		pCount := PrefixIPCount(p)
		pStartU, _ := IPv4ToUint32(p.Masked().Addr())
		pEndU := pStartU + uint32(pCount-1)

		cidrDetails[i] = CIDRDetail{
			CIDR:         p.String(),
			Netmask:      mask.String(),
			WildcardMask: wildcard.String(),
			IPCount:      pCount,
			StartIP:      p.Masked().Addr().String(),
			EndIP:        Uint32ToIPv4(pEndU).String(),
		}
	}

	rawDesc := r.Raw
	if rawDesc == "" {
		rawDesc = fmt.Sprintf("%s-%s", r.Start, r.End)
	}

	info := RangeInfo{
		Range:           rawDesc,
		StartIP:         r.Start.String(),
		EndIP:           r.End.String(),
		StartInteger:    startU,
		EndInteger:      endU,
		StartHex:        fmt.Sprintf("0x%08X", startU),
		EndHex:          fmt.Sprintf("0x%08X", endU),
		StartBinary:     FormatDottedBinary(r.Start),
		EndBinary:       FormatDottedBinary(r.End),
		TotalIPs:        totalIPs,
		CIDRCount:       len(prefixes),
		Scope:           scope,
		HistoricalClass: historicalClass,
		CIDRs:           cidrDetails,
	}

	// Single subnet enrichment
	if len(prefixes) == 1 {
		p := prefixes[0]
		info.IsSingleSubnet = true
		info.Netmask = PrefixMask(p.Bits()).String()
		info.WildcardMask = PrefixWildcard(p.Bits()).String()
		info.NetworkIP = r.Start.String()
		info.BroadcastIP = r.End.String()

		switch {
		case p.Bits() <= 30:
			info.UsableHostsCount = totalIPs - 2
			firstHost := Uint32ToIPv4(startU + 1)
			lastHost := Uint32ToIPv4(endU - 1)
			info.UsableHostRange = fmt.Sprintf("%s - %s", firstHost, lastHost)
		case p.Bits() == 31:
			// RFC 3021 Point-to-Point Links
			info.UsableHostsCount = 2
			info.UsableHostRange = fmt.Sprintf("%s - %s (RFC 3021 Point-to-Point)", r.Start, r.End)
		case p.Bits() == 32:
			info.UsableHostsCount = 1
			info.UsableHostRange = fmt.Sprintf("%s (Single Host)", r.Start)
		}
	}

	return info, nil
}

// FormatDottedBinary returns an IPv4 address formatted as 8-bit dotted binary octets.
func FormatDottedBinary(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("%08b.%08b.%08b.%08b", b[0], b[1], b[2], b[3])
}

// GetHistoricalClass returns the historical classful network class for an IPv4 address.
func GetHistoricalClass(ip netip.Addr) string {
	if !ip.IsValid() || !ip.Is4() {
		return "Unknown"
	}
	firstOctet := ip.As4()[0]
	switch {
	case firstOctet <= 127:
		return "Class A (Historical /8)"
	case firstOctet <= 191:
		return "Class B (Historical /16)"
	case firstOctet <= 223:
		return "Class C (Historical /24)"
	case firstOctet <= 239:
		return "Class D (Multicast)"
	default:
		return "Class E (Reserved)"
	}
}

// GetIPScope returns the architectural scope and RFC specification for an IPv4 address.
func GetIPScope(ip netip.Addr) string {
	if !ip.IsValid() || !ip.Is4() {
		return "Invalid"
	}

	u, err := IPv4ToUint32(ip)
	if err != nil {
		return "Invalid"
	}

	// Helper for CIDR range matching
	inRange := func(cidrStr string) bool {
		p, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			return false
		}
		return p.Contains(ip)
	}

	switch {
	case inRange("0.0.0.0/8"):
		return "Current Network / 'This Host' (RFC 1122)"
	case inRange("10.0.0.0/8"):
		return "Private-Use / Internal (RFC 1918)"
	case inRange("100.64.0.0/10"):
		return "Carrier-Grade NAT / Shared Space (RFC 6598)"
	case inRange("127.0.0.0/8"):
		return "Loopback (RFC 1122)"
	case inRange("169.254.0.0/16"):
		return "Link-Local / APIPA (RFC 3927)"
	case inRange("172.16.0.0/12"):
		return "Private-Use / Internal (RFC 1918)"
	case inRange("192.0.0.0/24"):
		return "IETF Protocol Assignments (RFC 6890)"
	case inRange("192.0.2.0/24"):
		return "Documentation / TEST-NET-1 (RFC 5737)"
	case inRange("192.88.99.0/24"):
		return "6to4 Relay Anycast (RFC 7526)"
	case inRange("192.168.0.0/16"):
		return "Private-Use / Internal (RFC 1918)"
	case inRange("198.18.0.0/15"):
		return "Benchmark Testing (RFC 2544)"
	case inRange("198.51.100.0/24"):
		return "Documentation / TEST-NET-2 (RFC 5737)"
	case inRange("203.0.113.0/24"):
		return "Documentation / TEST-NET-3 (RFC 5737)"
	case inRange("224.0.0.0/4"):
		return "Multicast (RFC 5771)"
	case inRange("240.0.0.0/4") && u != 0xFFFFFFFF:
		return "Reserved for Future Use (RFC 1112)"
	case u == 0xFFFFFFFF:
		return "Limited Broadcast (RFC 919)"
	default:
		return "Public Internet (Global Unicast)"
	}
}

// FormatText formats RangeInfo into a human-readable, beautifully aligned diagnostic report.
func (info RangeInfo) FormatText() string {
	return info.FormatTextWithColor(false)
}

// FormatTextWithColor formats RangeInfo, optionally applying TTY ANSI colorization to bitmasks.
func (info RangeInfo) FormatTextWithColor(colorize bool) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("IP Range Analysis & Details\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("%-18s %s\n", "Range:", info.Range))
	sb.WriteString(fmt.Sprintf("%-18s %d\n", "Total Addresses:", info.TotalIPs))
	sb.WriteString(fmt.Sprintf("%-18s %d\n", "CIDR Block(s):", info.CIDRCount))
	sb.WriteString(fmt.Sprintf("%-18s %s\n", "Scope:", info.Scope))
	sb.WriteString(fmt.Sprintf("%-18s %s\n", "Historical Class:", info.HistoricalClass))

	startBin := info.StartBinary
	endBin := info.EndBinary
	if colorize && len(info.CIDRs) > 0 {
		// Extract prefix bits if single subnet or first block
		firstCIDR := info.CIDRs[0].CIDR
		if prefix, err := netip.ParsePrefix(firstCIDR); err == nil {
			startBin = ColorizeBinary(startBin, prefix.Bits())
			endBin = ColorizeBinary(endBin, prefix.Bits())
		}
	}

	sb.WriteString("\nStart Address:\n")
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP:", info.StartIP))
	sb.WriteString(fmt.Sprintf("  %-16s %d\n", "Integer:", info.StartInteger))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Hex:", info.StartHex))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Binary:", startBin))

	sb.WriteString("\nEnd Address:\n")
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP:", info.EndIP))
	sb.WriteString(fmt.Sprintf("  %-16s %d\n", "Integer:", info.EndInteger))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Hex:", info.EndHex))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Binary:", endBin))

	if colorize {
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Bit Breakdown:", FormatBinaryLegend()))
	}

	if info.IsSingleSubnet {
		sb.WriteString("\nSubnet Details:\n")
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Network IP:", info.NetworkIP))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Broadcast IP:", info.BroadcastIP))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Netmask:", info.Netmask))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Wildcard Mask:", info.WildcardMask))
		sb.WriteString(fmt.Sprintf("  %-16s %d (%s)\n", "Usable Hosts:", info.UsableHostsCount, info.UsableHostRange))
	}

	sb.WriteString("\nCIDR Decomposition:\n")
	for i, c := range info.CIDRs {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, c.CIDR))
		sb.WriteString(fmt.Sprintf("      %-14s %s - %s (%d address(es))\n", "Range:", c.StartIP, c.EndIP, c.IPCount))
		sb.WriteString(fmt.Sprintf("      %-14s %s\n", "Netmask:", c.Netmask))
		sb.WriteString(fmt.Sprintf("      %-14s %s\n", "Wildcard:", c.WildcardMask))
	}
	sb.WriteString("================================================================================")
	return sb.String()
}
