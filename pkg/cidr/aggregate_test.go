package cidr_test

import (
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestAggregateCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "overlapping subnets merged into supernet",
			input:    []string{"10.0.0.0/24", "10.0.0.128/25"},
			expected: []string{"10.0.0.0/24"},
		},
		{
			name:     "adjacent /24s merged into /23",
			input:    []string{"10.0.0.0/24", "10.0.1.0/24"},
			expected: []string{"10.0.0.0/23"},
		},
		{
			name:     "four adjacent /24s merged into /22",
			input:    []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"},
			expected: []string{"192.168.0.0/22"},
		},
		{
			name:     "non-adjacent subnets kept distinct",
			input:    []string{"10.0.0.0/24", "10.0.2.0/24"},
			expected: []string{"10.0.0.0/24", "10.0.2.0/24"},
		},
		{
			name:     "out-of-order prefixes aggregated correctly",
			input:    []string{"10.0.1.0/24", "10.0.0.0/24"},
			expected: []string{"10.0.0.0/23"},
		},
		{
			name:     "duplicate CIDRs deduplicated",
			input:    []string{"172.16.0.0/16", "172.16.0.0/16"},
			expected: []string{"172.16.0.0/16"},
		},
		{
			name:     "single prefix",
			input:    []string{"10.5.0.0/16"},
			expected: []string{"10.5.0.0/16"},
		},
		{
			name:     "IPv6 adjacent prefixes merged",
			input:    []string{"2001:db8::/65", "2001:db8:0:0:8000::/65"},
			expected: []string{"2001:db8::/64"},
		},
		{
			name:     "IPv6 overlapping prefixes merged",
			input:    []string{"2001:db8::/32", "2001:db8:1::/64"},
			expected: []string{"2001:db8::/32"},
		},
		{
			name:     "mixed IPv4 and IPv6 aggregated independently",
			input:    []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8::/65", "2001:db8:0:0:8000::/65"},
			expected: []string{"10.0.0.0/23", "2001:db8::/64"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ranges []cidr.IPRange
			for _, s := range tc.input {
				r, err := cidr.ParseRange(s)
				if err != nil {
					t.Fatalf("failed to parse test range %q: %v", s, err)
				}
				ranges = append(ranges, r)
			}

			result, err := cidr.AggregateCIDRs(ranges)
			if err != nil {
				t.Fatalf("unexpected error from AggregateCIDRs: %v", err)
			}
			var gotStrs []string
			for _, p := range result {
				gotStrs = append(gotStrs, p.String())
			}

			if len(gotStrs) != len(tc.expected) {
				t.Fatalf("got %v (%d CIDRs), want %v (%d CIDRs)", gotStrs, len(gotStrs), tc.expected, len(tc.expected))
			}
			for i := range gotStrs {
				if gotStrs[i] != tc.expected[i] {
					t.Errorf("result[%d]: got %s, want %s", i, gotStrs[i], tc.expected[i])
				}
			}
		})
	}
}
