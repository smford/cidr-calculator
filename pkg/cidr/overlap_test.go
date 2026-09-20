package cidr_test

import (
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestCheckOverlap(t *testing.T) {
	tests := []struct {
		name          string
		rangeA        string
		rangeB        string
		wantOverlap   bool
		wantIntersect string
		wantErr       bool
	}{
		{
			name:        "disjoint subnets",
			rangeA:      "10.0.0.0/24",
			rangeB:      "10.0.1.0/24",
			wantOverlap: false,
		},
		{
			name:          "partial overlap",
			rangeA:        "10.0.0.100-10.0.0.200",
			rangeB:        "10.0.0.150-10.0.0.250",
			wantOverlap:   true,
			wantIntersect: "10.0.0.150-10.0.0.200",
		},
		{
			name:          "complete containment",
			rangeA:        "10.0.0.0/16",
			rangeB:        "10.0.5.0/24",
			wantOverlap:   true,
			wantIntersect: "10.0.5.0-10.0.5.255",
		},
		{
			name:          "identical ranges",
			rangeA:        "192.168.1.0/24",
			rangeB:        "192.168.1.0/24",
			wantOverlap:   true,
			wantIntersect: "192.168.1.0-192.168.1.255",
		},
		{
			name:          "single IP overlap",
			rangeA:        "192.168.1.10",
			rangeB:        "192.168.1.10",
			wantOverlap:   true,
			wantIntersect: "192.168.1.10-192.168.1.10",
		},
		{
			name:        "IPv4 and IPv6 comparison error",
			rangeA:      "192.168.1.0/24",
			rangeB:      "2001:db8::/32",
			wantOverlap: false,
			wantErr:     true,
		},
		{
			name:          "IPv6 overlap",
			rangeA:        "2001:db8::/32",
			rangeB:        "2001:db8:1::/64",
			wantOverlap:   true,
			wantIntersect: "2001:db8:1::-2001:db8:1:0:ffff:ffff:ffff:ffff",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rA, err := cidr.ParseRange(tc.rangeA)
			if err != nil {
				t.Fatalf("failed to parse rangeA %q: %v", tc.rangeA, err)
			}
			rB, err := cidr.ParseRange(tc.rangeB)
			if err != nil {
				t.Fatalf("failed to parse rangeB %q: %v", tc.rangeB, err)
			}

			res, err := cidr.CheckOverlap(rA, rB)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res.Overlaps != tc.wantOverlap {
				t.Errorf("overlaps: got %v, want %v", res.Overlaps, tc.wantOverlap)
			}

			if tc.wantOverlap && tc.wantIntersect != "" {
				if res.Intersection == nil {
					t.Fatalf("expected intersection %s, got nil", tc.wantIntersect)
				}
				if res.Intersection.Raw != tc.wantIntersect {
					t.Errorf("intersection: got %s, want %s", res.Intersection.Raw, tc.wantIntersect)
				}
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name      string
		container string
		target    string
		want      bool
	}{
		{
			name:      "supernet contains subnet",
			container: "10.0.0.0/16",
			target:    "10.0.5.0/24",
			want:      true,
		},
		{
			name:      "supernet contains single IP",
			container: "10.0.0.0/16",
			target:    "10.0.5.1",
			want:      true,
		},
		{
			name:      "subnet does not contain supernet",
			container: "10.0.5.0/24",
			target:    "10.0.0.0/16",
			want:      false,
		},
		{
			name:      "disjoint ranges",
			container: "192.168.1.0/24",
			target:    "10.0.0.1",
			want:      false,
		},
		{
			name:      "identical ranges contain each other",
			container: "172.16.0.0/12",
			target:    "172.16.0.0/12",
			want:      true,
		},
		{
			name:      "mixed v4 and v6 does not contain",
			container: "10.0.0.0/16",
			target:    "2001:db8::1",
			want:      false,
		},
		{
			name:      "IPv6 containment",
			container: "2001:db8::/32",
			target:    "2001:db8:abcd::1",
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rContainer, err := cidr.ParseRange(tc.container)
			if err != nil {
				t.Fatalf("failed to parse container %q: %v", tc.container, err)
			}
			rTarget, err := cidr.ParseRange(tc.target)
			if err != nil {
				t.Fatalf("failed to parse target %q: %v", tc.target, err)
			}

			got := cidr.Contains(rContainer, rTarget)
			if got != tc.want {
				t.Errorf("Contains(%s, %s): got %v, want %v", tc.container, tc.target, got, tc.want)
			}
		})
	}
}
