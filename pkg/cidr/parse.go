package cidr

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// IPRange represents a parsed IPv4 range with start and end addresses.
type IPRange struct {
	Raw   string     `json:"raw"`
	Start netip.Addr `json:"start"`
	End   netip.Addr `json:"end"`
}

// ParseRange parses an IPv4 range string into an IPRange struct.
// Supported formats:
//   - "192.168.1.1-192.168.1.10" or "192.168.1.1 - 192.168.1.10"
//   - "192.168.1.1..192.168.1.10"
//   - "192.168.1.1 to 192.168.1.10"
//   - "192.168.1.1,192.168.1.10" or "192.168.1.1, 192.168.1.10"
//   - "192.168.1.1-10" (shorthand notation)
//   - "192.168.1.0/24" (CIDR notation)
//   - "192.168.1.1" (single IP, treated as start=end)
func ParseRange(s string) (IPRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return IPRange{}, errors.New("empty IP range string")
	}

	// 1. CIDR notation
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return IPRange{}, fmt.Errorf("invalid CIDR prefix %q: %w", s, err)
		}
		masked := prefix.Masked()
		if prefix.Addr().Is4() {
			startU, err := IPv4ToUint32(masked.Addr())
			if err != nil {
				return IPRange{}, err
			}

			pBits := prefix.Bits()
			hostBits := 32 - pBits
			var endU uint32
			if hostBits == 32 {
				endU = 0xFFFFFFFF
			} else {
				endU = startU | ((1 << hostBits) - 1)
			}

			return IPRange{
				Raw:   s,
				Start: masked.Addr(),
				End:   Uint32ToIPv4(endU),
			}, nil
		}

		// IPv6 CIDR prefix
		pBits := prefix.Bits()
		b := masked.Addr().As16()
		for i := pBits; i < 128; i++ {
			byteIdx := i / 8
			bitIdx := 7 - (i % 8)
			b[byteIdx] |= (1 << bitIdx)
		}
		return IPRange{
			Raw:   s,
			Start: masked.Addr(),
			End:   netip.AddrFrom16(b),
		}, nil
	}

	// 2. Plus offset notation (e.g., "192.168.1.10+5")
	if strings.Contains(s, "+") {
		idx := strings.Index(s, "+")
		left := strings.TrimSpace(s[:idx])
		right := strings.TrimSpace(s[idx+1:])

		startAddr, err := netip.ParseAddr(left)
		if err != nil {
			return IPRange{}, fmt.Errorf("invalid start IP %q: %w", left, err)
		}
		if !startAddr.Is4() {
			return IPRange{}, ErrIPv6NotSupported
		}

		offset, err := strconv.ParseUint(right, 10, 64)
		if err != nil {
			return IPRange{}, fmt.Errorf("invalid offset %q in range %q: %w", right, s, err)
		}

		startU, err := IPv4ToUint32(startAddr)
		if err != nil {
			return IPRange{}, err
		}

		if uint64(startU)+offset > 0xFFFFFFFF {
			return IPRange{}, fmt.Errorf("offset %d exceeds IPv4 address space from start IP %s", offset, startAddr)
		}

		endU := uint32(uint64(startU) + offset)
		endAddr := Uint32ToIPv4(endU)

		return IPRange{
			Raw:   s,
			Start: startAddr,
			End:   endAddr,
		}, nil
	}

	// 3. Delimited range formats
	delimiters := []string{" - ", "..", " to ", " TO ", " To ", ",", "-"}
	for _, delim := range delimiters {
		if idx := strings.Index(s, delim); idx != -1 {
			left := strings.TrimSpace(s[:idx])
			right := strings.TrimSpace(s[idx+len(delim):])

			startAddr, err := netip.ParseAddr(left)
			if err != nil {
				return IPRange{}, fmt.Errorf("invalid start IP %q: %w", left, err)
			}

			// Check if right side is a full IP
			endAddr, err := netip.ParseAddr(right)
			if err == nil {
				if startAddr.Is4() != endAddr.Is4() {
					return IPRange{}, errors.New("cannot mix IPv4 and IPv6 addresses in range")
				}
				if startAddr.Compare(endAddr) > 0 {
					return IPRange{}, fmt.Errorf("%w: %s > %s", ErrStartGreaterThanEnd, startAddr, endAddr)
				}
				return IPRange{
					Raw:   s,
					Start: startAddr,
					End:   endAddr,
				}, nil
			}

			// Check if right side is shorthand octet notation (IPv4 only)
			if startAddr.Is4() && !strings.Contains(right, ".") {
				if lastOctet, convErr := strconv.Atoi(right); convErr == nil && lastOctet >= 0 && lastOctet <= 255 {
					b := startAddr.As4()
					b[3] = byte(lastOctet)
					endAddr = netip.AddrFrom4(b)
					if startAddr.Compare(endAddr) > 0 {
						return IPRange{}, fmt.Errorf("%w: %s > %s", ErrStartGreaterThanEnd, startAddr, endAddr)
					}
					return IPRange{
						Raw:   s,
						Start: startAddr,
						End:   endAddr,
					}, nil
				}
			}

			return IPRange{}, fmt.Errorf("invalid end IP %q in range %q", right, s)
		}
	}

	// 4. Single IP notation (treated as a /32 or /128 single IP range)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IPRange{}, fmt.Errorf("invalid IP or range format %q: %w", s, err)
	}

	return IPRange{
		Raw:   s,
		Start: addr,
		End:   addr,
	}, nil
}

// ParseArgs parses command-line arguments into a slice of IPRange.
// Examples:
//   - ["192.168.1.1-192.168.1.10"] -> 1 range
//   - ["192.168.1.1", "192.168.1.10"] -> 1 range
//   - ["192.168.1.1", "-", "192.168.1.10"] -> 1 range
//   - ["10.0.0.1-10", "192.168.1.0/28"] -> 2 ranges
func ParseArgs(args []string) ([]IPRange, error) {
	if len(args) == 0 {
		return nil, errors.New("no IP range provided")
	}

	// Case 1: 3 args with "-", "to", or "+" in between, e.g. ["192.168.1.1", "-", "192.168.1.10"] or ["192.168.1.10", "+", "5"]
	if len(args) == 3 && (args[1] == "-" || strings.EqualFold(args[1], "to") || args[1] == "+") {
		sep := args[1]
		if strings.EqualFold(sep, "to") {
			sep = "-"
		}
		r, err := ParseRange(args[0] + sep + args[2])
		if err != nil {
			return nil, err
		}
		return []IPRange{r}, nil
	}

	// Case 2: 2 args that are start and end IPs, or base IP and +offset, e.g. ["192.168.1.10", "+5"]
	if len(args) == 2 {
		if strings.HasPrefix(args[1], "+") {
			r, err := ParseRange(args[0] + args[1])
			if err == nil {
				return []IPRange{r}, nil
			}
		}
		// If both args don't have range delimiters/slashes and first parses as IP
		if !strings.ContainsAny(args[0], "-/.,+") || isIP(args[0]) {
			r, err := ParseRange(args[0] + "-" + args[1])
			if err == nil {
				return []IPRange{r}, nil
			}
		}
	}

	// Case 3: Each argument is parsed as its own range specification
	var ranges []IPRange
	for _, arg := range args {
		r, err := ParseRange(arg)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}

	return ranges, nil
}

func isIP(s string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil && addr.IsValid()
}
