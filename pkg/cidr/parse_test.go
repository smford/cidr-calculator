package cidr_test

import (
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantStart   string
		wantEnd     string
		expectError bool
	}{
		{
			name:      "hyphen standard",
			input:     "192.168.1.10-192.168.1.20",
			wantStart: "192.168.1.10",
			wantEnd:   "192.168.1.20",
		},
		{
			name:      "hyphen with spaces",
			input:     "  192.168.1.10 - 192.168.1.20  ",
			wantStart: "192.168.1.10",
			wantEnd:   "192.168.1.20",
		},
		{
			name:      "double dot notation",
			input:     "10.0.0.1..10.0.0.50",
			wantStart: "10.0.0.1",
			wantEnd:   "10.0.0.50",
		},
		{
			name:      "comma separated",
			input:     "172.16.0.1, 172.16.0.100",
			wantStart: "172.16.0.1",
			wantEnd:   "172.16.0.100",
		},
		{
			name:      "word 'to'",
			input:     "192.168.0.1 to 192.168.0.254",
			wantStart: "192.168.0.1",
			wantEnd:   "192.168.0.254",
		},
		{
			name:      "shorthand last octet",
			input:     "192.168.1.10-20",
			wantStart: "192.168.1.10",
			wantEnd:   "192.168.1.20",
		},
		{
			name:      "CIDR block /24",
			input:     "192.168.1.0/24",
			wantStart: "192.168.1.0",
			wantEnd:   "192.168.1.255",
		},
		{
			name:      "CIDR block unmasked /24",
			input:     "192.168.1.50/24",
			wantStart: "192.168.1.0",
			wantEnd:   "192.168.1.255",
		},
		{
			name:      "CIDR /32 single host",
			input:     "10.1.2.3/32",
			wantStart: "10.1.2.3",
			wantEnd:   "10.1.2.3",
		},
		{
			name:      "single IP",
			input:     "192.168.1.100",
			wantStart: "192.168.1.100",
			wantEnd:   "192.168.1.100",
		},
		{
			name:      "plus offset notation standard",
			input:     "192.168.1.10+5",
			wantStart: "192.168.1.10",
			wantEnd:   "192.168.1.15",
		},
		{
			name:      "plus offset notation with spaces",
			input:     " 192.168.1.10 + 5 ",
			wantStart: "192.168.1.10",
			wantEnd:   "192.168.1.15",
		},
		{
			name:      "plus offset cross octet rollover",
			input:     "192.168.1.250+10",
			wantStart: "192.168.1.250",
			wantEnd:   "192.168.2.4",
		},
		{
			name:      "plus offset zero",
			input:     "10.0.0.1+0",
			wantStart: "10.0.0.1",
			wantEnd:   "10.0.0.1",
		},
		{
			name:        "plus offset overflow error",
			input:       "255.255.255.255+1",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "start greater than end",
			input:       "192.168.1.50-192.168.1.10",
			expectError: true,
		},
		{
			name:        "shorthand start greater than end",
			input:       "192.168.1.50-10",
			expectError: true,
		},
		{
			name:        "invalid IP",
			input:       "999.999.999.999-10.0.0.1",
			expectError: true,
		},
		{
			name:        "IPv6 range accepted",
			input:       "2001:db8::1-2001:db8::2",
			wantStart:   "2001:db8::1",
			wantEnd:     "2001:db8::2",
			expectError: false,
		},
		{
			name:        "mixed IPv4 and IPv6 rejected",
			input:       "192.168.1.1-2001:db8::2",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := cidr.ParseRange(tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if r.Start.String() != tc.wantStart {
				t.Errorf("start: got %s, want %s", r.Start, tc.wantStart)
			}
			if r.End.String() != tc.wantEnd {
				t.Errorf("end: got %s, want %s", r.End, tc.wantEnd)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCount   int
		expectError bool
	}{
		{
			name:      "single arg with range",
			args:      []string{"192.168.1.1-192.168.1.10"},
			wantCount: 1,
		},
		{
			name:      "two args representing range",
			args:      []string{"192.168.1.1", "192.168.1.10"},
			wantCount: 1,
		},
		{
			name:      "three args with hyphen separator",
			args:      []string{"192.168.1.1", "-", "192.168.1.10"},
			wantCount: 1,
		},
		{
			name:      "three args with to separator",
			args:      []string{"192.168.1.1", "to", "192.168.1.10"},
			wantCount: 1,
		},
		{
			name:      "three args with plus separator",
			args:      []string{"192.168.1.10", "+", "5"},
			wantCount: 1,
		},
		{
			name:      "two args with plus offset",
			args:      []string{"192.168.1.10", "+5"},
			wantCount: 1,
		},
		{
			name:      "multiple distinct ranges",
			args:      []string{"10.0.0.1-10.0.0.5", "192.168.1.1-192.168.1.5"},
			wantCount: 2,
		},
		{
			name:        "empty args",
			args:        []string{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ranges, err := cidr.ParseArgs(tc.args)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ranges) != tc.wantCount {
				t.Fatalf("expected %d ranges, got %d", tc.wantCount, len(ranges))
			}
		})
	}
}
