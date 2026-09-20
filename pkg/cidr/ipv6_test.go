package cidr_test

import (
	"net/netip"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestRangeToCIDRsV6(t *testing.T) {
	tests := []struct {
		name      string
		start     string
		end       string
		wantCIDRs []string
		wantErr   bool
	}{
		{
			name:      "single IPv6 host",
			start:     "2001:db8::1",
			end:       "2001:db8::1",
			wantCIDRs: []string{"2001:db8::1/128"},
		},
		{
			name:      "exact /120 boundary (256 addresses)",
			start:     "2001:db8::100",
			end:       "2001:db8::1ff",
			wantCIDRs: []string{"2001:db8::100/120"},
		},
		{
			name:      "exact /64 boundary",
			start:     "2001:db8::",
			end:       "2001:db8::ffff:ffff:ffff:ffff",
			wantCIDRs: []string{"2001:db8::/64"},
		},
		{
			name:  "unaligned small range (5 addresses)",
			start: "2001:db8::1",
			end:   "2001:db8::5",
			wantCIDRs: []string{
				"2001:db8::1/128",
				"2001:db8::2/127",
				"2001:db8::4/127",
			},
		},
		{
			name:    "start greater than end",
			start:   "2001:db8::10",
			end:     "2001:db8::1",
			wantErr: true,
		},
		{
			name:    "IPv4 passed to V6 func",
			start:   "192.168.1.1",
			end:     "192.168.1.5",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := netip.MustParseAddr(tc.start)
			e := netip.MustParseAddr(tc.end)

			cidrs, err := cidr.RangeToCIDRsV6(s, e)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(cidrs) != len(tc.wantCIDRs) {
				t.Fatalf("got %d CIDRs, want %d. Got: %v", len(cidrs), len(tc.wantCIDRs), cidrs)
			}
			for i, want := range tc.wantCIDRs {
				if cidrs[i].String() != want {
					t.Errorf("CIDR[%d]: got %s, want %s", i, cidrs[i], want)
				}
			}
		})
	}
}

func TestRangeToCIDRsAny(t *testing.T) {
	// Test IPv4 dispatch
	v4Start := netip.MustParseAddr("192.168.1.0")
	v4End := netip.MustParseAddr("192.168.1.255")
	v4Prefixes, err := cidr.RangeToCIDRsAny(v4Start, v4End)
	if err != nil {
		t.Fatalf("unexpected error for IPv4: %v", err)
	}
	if len(v4Prefixes) != 1 || v4Prefixes[0].String() != "192.168.1.0/24" {
		t.Errorf("unexpected IPv4 prefix: %v", v4Prefixes)
	}

	// Test IPv6 dispatch
	v6Start := netip.MustParseAddr("2001:db8::")
	v6End := netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff")
	v6Prefixes, err := cidr.RangeToCIDRsAny(v6Start, v6End)
	if err != nil {
		t.Fatalf("unexpected error for IPv6: %v", err)
	}
	if len(v6Prefixes) != 1 || v6Prefixes[0].String() != "2001:db8::/64" {
		t.Errorf("unexpected IPv6 prefix: %v", v6Prefixes)
	}

	// Test mixed v4 and v6
	_, err = cidr.RangeToCIDRsAny(v4Start, v6End)
	if err == nil {
		t.Errorf("expected error for mixed IPv4 and IPv6, got nil")
	}
}
