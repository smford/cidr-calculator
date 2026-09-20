package cidr_test

import (
	"net/netip"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestSplitCIDR(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		targetBits int
		wantCIDRs  []string
		wantErr    bool
	}{
		{
			name:       "split /22 into four /24 subnets",
			parent:     "10.0.0.0/22",
			targetBits: 24,
			wantCIDRs: []string{
				"10.0.0.0/24",
				"10.0.1.0/24",
				"10.0.2.0/24",
				"10.0.3.0/24",
			},
		},
		{
			name:       "split /24 into /24 returns self",
			parent:     "192.168.1.0/24",
			targetBits: 24,
			wantCIDRs: []string{
				"192.168.1.0/24",
			},
		},
		{
			name:       "split unmasked CIDR masks correctly",
			parent:     "10.0.1.5/22",
			targetBits: 24,
			wantCIDRs: []string{
				"10.0.0.0/24",
				"10.0.1.0/24",
				"10.0.2.0/24",
				"10.0.3.0/24",
			},
		},
		{
			name:       "targetBits less than parent bits",
			parent:     "10.0.0.0/22",
			targetBits: 20,
			wantErr:    true,
		},
		{
			name:       "targetBits exceeds 32 for IPv4",
			parent:     "10.0.0.0/24",
			targetBits: 33,
			wantErr:    true,
		},
		{
			name:       "split exceeds limit (more than 65536 subnets)",
			parent:     "10.0.0.0/8",
			targetBits: 25, // 17 bits diff -> 131072 subnets
			wantErr:    true,
		},
		{
			name:       "IPv6 split /60 into sixteen /64 subnets",
			parent:     "2001:db8::/60",
			targetBits: 64,
			wantCIDRs: []string{
				"2001:db8::/64",
				"2001:db8:0:1::/64",
				"2001:db8:0:2::/64",
				"2001:db8:0:3::/64",
				"2001:db8:0:4::/64",
				"2001:db8:0:5::/64",
				"2001:db8:0:6::/64",
				"2001:db8:0:7::/64",
				"2001:db8:0:8::/64",
				"2001:db8:0:9::/64",
				"2001:db8:0:a::/64",
				"2001:db8:0:b::/64",
				"2001:db8:0:c::/64",
				"2001:db8:0:d::/64",
				"2001:db8:0:e::/64",
				"2001:db8:0:f::/64",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent, err := netip.ParsePrefix(tc.parent)
			if err != nil {
				t.Fatalf("failed to parse parent %q: %v", tc.parent, err)
			}

			subnets, err := cidr.SplitCIDR(parent, tc.targetBits)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(subnets) != len(tc.wantCIDRs) {
				t.Fatalf("got %d subnets, want %d: %v", len(subnets), len(tc.wantCIDRs), subnets)
			}
			for i, want := range tc.wantCIDRs {
				if subnets[i].String() != want {
					t.Errorf("subnet[%d]: got %s, want %s", i, subnets[i], want)
				}
			}
		})
	}
}

func TestSplitCIDRByCount(t *testing.T) {
	tests := []struct {
		name      string
		parent    string
		count     int
		wantCIDRs []string
		wantErr   bool
	}{
		{
			name:   "split /22 into 4 subnets",
			parent: "10.0.0.0/22",
			count:  4,
			wantCIDRs: []string{
				"10.0.0.0/24",
				"10.0.1.0/24",
				"10.0.2.0/24",
				"10.0.3.0/24",
			},
		},
		{
			name:   "split /22 into 3 subnets (rounds up to power of 2: 4 subnets)",
			parent: "10.0.0.0/22",
			count:  3,
			wantCIDRs: []string{
				"10.0.0.0/24",
				"10.0.1.0/24",
				"10.0.2.0/24",
				"10.0.3.0/24",
			},
		},
		{
			name:   "count 1 returns parent",
			parent: "10.0.0.0/24",
			count:  1,
			wantCIDRs: []string{
				"10.0.0.0/24",
			},
		},
		{
			name:    "zero count",
			parent:  "10.0.0.0/24",
			count:   0,
			wantErr: true,
		},
		{
			name:    "negative count",
			parent:  "10.0.0.0/24",
			count:   -1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent, err := netip.ParsePrefix(tc.parent)
			if err != nil {
				t.Fatalf("failed to parse parent %q: %v", tc.parent, err)
			}

			subnets, err := cidr.SplitCIDRByCount(parent, tc.count)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(subnets) != len(tc.wantCIDRs) {
				t.Fatalf("got %d subnets, want %d: %v", len(subnets), len(tc.wantCIDRs), subnets)
			}
			for i, want := range tc.wantCIDRs {
				if subnets[i].String() != want {
					t.Errorf("subnet[%d]: got %s, want %s", i, subnets[i], want)
				}
			}
		})
	}
}
