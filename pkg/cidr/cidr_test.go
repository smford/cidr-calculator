package cidr_test

import (
	"net/netip"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

func prefixesToStrings(prefixes []netip.Prefix) []string {
	res := make([]string, len(prefixes))
	for i, p := range prefixes {
		res[i] = p.String()
	}
	return res
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRangeToCIDRs(t *testing.T) {
	tests := []struct {
		name        string
		start       string
		end         string
		expected    []string
		expectError bool
	}{
		{
			name:     "single IP",
			start:    "192.168.1.1",
			end:      "192.168.1.1",
			expected: []string{"192.168.1.1/32"},
		},
		{
			name:     "exact /24 boundary",
			start:    "10.0.0.0",
			end:      "10.0.0.255",
			expected: []string{"10.0.0.0/24"},
		},
		{
			name:     "exact /16 boundary",
			start:    "172.16.0.0",
			end:      "172.16.255.255",
			expected: []string{"172.16.0.0/16"},
		},
		{
			name:     "entire IPv4 space",
			start:    "0.0.0.0",
			end:      "255.255.255.255",
			expected: []string{"0.0.0.0/0"},
		},
		{
			name:  "unaligned small range 192.168.1.10 to 192.168.1.20",
			start: "192.168.1.10",
			end:   "192.168.1.20",
			expected: []string{
				"192.168.1.10/31",
				"192.168.1.12/30",
				"192.168.1.16/30",
				"192.168.1.20/32",
			},
		},
		{
			name:  "range 192.168.1.1 to 192.168.1.5",
			start: "192.168.1.1",
			end:   "192.168.1.5",
			expected: []string{
				"192.168.1.1/32",
				"192.168.1.2/31",
				"192.168.1.4/31",
			},
		},
		{
			name:     "high boundary edge case",
			start:    "255.255.255.254",
			end:      "255.255.255.255",
			expected: []string{"255.255.255.254/31"},
		},
		{
			name:     "highest single IP",
			start:    "255.255.255.255",
			end:      "255.255.255.255",
			expected: []string{"255.255.255.255/32"},
		},
		{
			name:     "lowest boundary edge case",
			start:    "0.0.0.0",
			end:      "0.0.0.1",
			expected: []string{"0.0.0.0/31"},
		},
		{
			name:        "start greater than end",
			start:       "192.168.1.20",
			end:         "192.168.1.10",
			expectError: true,
		},
		{
			name:        "IPv6 rejected for start",
			start:       "::1",
			end:         "192.168.1.1",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startAddr, err := netip.ParseAddr(tc.start)
			if err != nil {
				t.Fatalf("failed to parse start IP: %v", err)
			}
			endAddr, err := netip.ParseAddr(tc.end)
			if err != nil {
				t.Fatalf("failed to parse end IP: %v", err)
			}

			prefixes, err := cidr.RangeToCIDRs(startAddr, endAddr)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			actual := prefixesToStrings(prefixes)
			if !equalSlices(actual, tc.expected) {
				t.Errorf("RangeToCIDRs(%s, %s)\n got:  %v\n want: %v", tc.start, tc.end, actual, tc.expected)
			}

			// Validate IP count property
			totalExpected, err := cidr.TotalIPs(startAddr, endAddr)
			if err != nil {
				t.Fatalf("TotalIPs error: %v", err)
			}
			var totalFromCIDRs uint64
			for _, p := range prefixes {
				totalFromCIDRs += cidr.PrefixIPCount(p)
			}
			if totalExpected != totalFromCIDRs {
				t.Errorf("Total IP mismatch: expected %d, got from CIDRs %d", totalExpected, totalFromCIDRs)
			}
		})
	}
}

func TestIPv4Conversions(t *testing.T) {
	ip := mustAddr("192.168.1.1")
	u, err := cidr.IPv4ToUint32(ip)
	if err != nil {
		t.Fatalf("IPv4ToUint32 error: %v", err)
	}

	back := cidr.Uint32ToIPv4(u)
	if ip != back {
		t.Fatalf("roundtrip failed: got %s, want %s", back, ip)
	}

	// Test invalid / IPv6
	ipv6 := mustAddr("2001:db8::1")
	_, err = cidr.IPv4ToUint32(ipv6)
	if err == nil {
		t.Fatal("expected error converting IPv6 to uint32, got nil")
	}

	var invalid netip.Addr
	_, err = cidr.IPv4ToUint32(invalid)
	if err == nil {
		t.Fatal("expected error converting invalid addr, got nil")
	}
}

func TestGenerateAndAllIPs(t *testing.T) {
	start := mustAddr("192.168.1.10")
	end := mustAddr("192.168.1.15")

	ips, err := cidr.AllIPs(start, end)
	if err != nil {
		t.Fatalf("AllIPs error: %v", err)
	}

	if len(ips) != 6 {
		t.Fatalf("expected 6 IPs, got %d", len(ips))
	}

	expected := []string{
		"192.168.1.10",
		"192.168.1.11",
		"192.168.1.12",
		"192.168.1.13",
		"192.168.1.14",
		"192.168.1.15",
	}

	for i, ip := range ips {
		if ip.String() != expected[i] {
			t.Errorf("ip[%d]: got %s, want %s", i, ip.String(), expected[i])
		}
	}

	// Test early break in GenerateIPs
	var count int
	_ = cidr.GenerateIPs(start, end, func(addr netip.Addr) bool {
		count++
		return count < 3
	})
	if count != 3 {
		t.Errorf("expected early stop at 3, got %d", count)
	}

	// Test invalid range
	_, err = cidr.AllIPs(end, start)
	if err == nil {
		t.Fatal("expected error when start > end, got nil")
	}
}

func TestMaskAndWildcard(t *testing.T) {
	tests := []struct {
		bits         int
		wantMask     string
		wantWildcard string
	}{
		{0, "0.0.0.0", "255.255.255.255"},
		{24, "255.255.255.0", "0.0.0.255"},
		{30, "255.255.255.252", "0.0.0.3"},
		{31, "255.255.255.254", "0.0.0.1"},
		{32, "255.255.255.255", "0.0.0.0"},
	}

	for _, tc := range tests {
		mask := cidr.PrefixMask(tc.bits)
		wildcard := cidr.PrefixWildcard(tc.bits)
		if mask.String() != tc.wantMask {
			t.Errorf("/%d mask: got %s, want %s", tc.bits, mask.String(), tc.wantMask)
		}
		if wildcard.String() != tc.wantWildcard {
			t.Errorf("/%d wildcard: got %s, want %s", tc.bits, wildcard.String(), tc.wantWildcard)
		}
	}
}
