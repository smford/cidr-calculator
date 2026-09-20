package cidr_test

import (
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestExcludeRanges(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		exclusions []string
		wantCIDRs  []string
		wantErr    bool
	}{
		{
			name:       "exclude gateway IP",
			base:       "192.168.1.0/24",
			exclusions: []string{"192.168.1.1"},
			wantCIDRs: []string{
				"192.168.1.0/32",
				"192.168.1.2/31",
				"192.168.1.4/30",
				"192.168.1.8/29",
				"192.168.1.16/28",
				"192.168.1.32/27",
				"192.168.1.64/26",
				"192.168.1.128/25",
			},
		},
		{
			name:       "exclude middle DHCP block",
			base:       "10.0.0.0/24",
			exclusions: []string{"10.0.0.128-10.0.0.255"},
			wantCIDRs: []string{
				"10.0.0.0/25",
			},
		},
		{
			name:       "exclude entire range",
			base:       "192.168.1.0/24",
			exclusions: []string{"192.168.1.0/24"},
			wantCIDRs:  nil,
		},
		{
			name:       "disjoint exclusion",
			base:       "192.168.1.0/24",
			exclusions: []string{"10.0.0.0/24"},
			wantCIDRs: []string{
				"192.168.1.0/24",
			},
		},
		{
			name:       "multiple exclusions",
			base:       "192.168.1.0-192.168.1.15", // /28
			exclusions: []string{"192.168.1.0", "192.168.1.15"},
			wantCIDRs: []string{
				"192.168.1.1/32",
				"192.168.1.2/31",
				"192.168.1.4/30",
				"192.168.1.8/30",
				"192.168.1.12/31",
				"192.168.1.14/32",
			},
		},
		{
			name:       "IPv6 exclusion",
			base:       "2001:db8::10-2001:db8::1f",
			exclusions: []string{"2001:db8::10", "2001:db8::1f"},
			wantCIDRs: []string{
				"2001:db8::11/128",
				"2001:db8::12/127",
				"2001:db8::14/126",
				"2001:db8::18/126",
				"2001:db8::1c/127",
				"2001:db8::1e/128",
			},
		},
		{
			name:       "mixed IPv4 base and IPv6 exclusion error",
			base:       "192.168.1.0/24",
			exclusions: []string{"2001:db8::1"},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseR, err := cidr.ParseRange(tc.base)
			if err != nil {
				t.Fatalf("failed to parse base %q: %v", tc.base, err)
			}

			var exclRanges []cidr.IPRange
			for _, eStr := range tc.exclusions {
				eR, err := cidr.ParseRange(eStr)
				if err != nil {
					t.Fatalf("failed to parse exclusion %q: %v", eStr, err)
				}
				exclRanges = append(exclRanges, eR)
			}

			prefixes, err := cidr.ExcludeRanges(baseR, exclRanges)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(prefixes) != len(tc.wantCIDRs) {
				t.Fatalf("got %d prefixes, want %d: %v", len(prefixes), len(tc.wantCIDRs), prefixes)
			}
			for i, want := range tc.wantCIDRs {
				if prefixes[i].String() != want {
					t.Errorf("prefix[%d]: got %s, want %s", i, prefixes[i], want)
				}
			}
		})
	}
}
