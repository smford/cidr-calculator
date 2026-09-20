package cidr_test

import (
	"strings"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestConvertIP(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantType    cidr.InputType
		wantIPv4    string
		wantInteger uint32
		wantHex     string
		wantBin     string
		expectError bool
	}{
		{
			name:        "integer decimal",
			input:       "3232235786",
			wantType:    cidr.TypeInteger,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "hex with 0x uppercase",
			input:       "0xC0A8010A",
			wantType:    cidr.TypeHex,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "hex with 0x lowercase",
			input:       "0xc0a8010a",
			wantType:    cidr.TypeHex,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "hex without 0x",
			input:       "c0a8010a",
			wantType:    cidr.TypeHex,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "dotted binary",
			input:       "11000000.10101000.00000001.00001010",
			wantType:    cidr.TypeBinary,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "plain 32-bit binary",
			input:       "11000000101010000000000100001010",
			wantType:    cidr.TypeBinary,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "binary with 0b prefix",
			input:       "0b11000000101010000000000100001010",
			wantType:    cidr.TypeBinary,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "ipv4 dotted decimal",
			input:       "192.168.1.10",
			wantType:    cidr.TypeDottedDecimal,
			wantIPv4:    "192.168.1.10",
			wantInteger: 3232235786,
			wantHex:     "0xC0A8010A",
			wantBin:     "11000000.10101000.00000001.00001010",
		},
		{
			name:        "zero integer",
			input:       "0",
			wantType:    cidr.TypeInteger,
			wantIPv4:    "0.0.0.0",
			wantInteger: 0,
			wantHex:     "0x00000000",
			wantBin:     "00000000.00000000.00000000.00000000",
		},
		{
			name:        "maximum integer 4294967295",
			input:       "4294967295",
			wantType:    cidr.TypeInteger,
			wantIPv4:    "255.255.255.255",
			wantInteger: 4294967295,
			wantHex:     "0xFFFFFFFF",
			wantBin:     "11111111.11111111.11111111.11111111",
		},
		{
			name:        "overflow integer",
			input:       "4294967296",
			expectError: true,
		},
		{
			name:        "overflow hex",
			input:       "0x100000000",
			expectError: true,
		},
		{
			name:        "invalid input string",
			input:       "not-an-ip-1234z",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := cidr.ConvertIP(tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res.InputType != tc.wantType {
				t.Errorf("input type: got %s, want %s", res.InputType, tc.wantType)
			}
			if res.IPv4 != tc.wantIPv4 {
				t.Errorf("ipv4: got %s, want %s", res.IPv4, tc.wantIPv4)
			}
			if res.Integer != tc.wantInteger {
				t.Errorf("integer: got %d, want %d", res.Integer, tc.wantInteger)
			}
			if res.Hex != tc.wantHex {
				t.Errorf("hex: got %s, want %s", res.Hex, tc.wantHex)
			}
			if res.Binary != tc.wantBin {
				t.Errorf("binary: got %s, want %s", res.Binary, tc.wantBin)
			}

			// Verify text formatting excludes the input format itself
			formatted := res.FormatText()
			switch tc.wantType {
			case cidr.TypeInteger:
				if strings.Contains(formatted, "Integer:        ") {
					t.Errorf("expected format output not to repeat Integer, got:\n%s", formatted)
				}
				if !strings.Contains(formatted, "IPv4 Address:") || !strings.Contains(formatted, "Hexadecimal:") || !strings.Contains(formatted, "Binary:") {
					t.Errorf("expected other types in output, got:\n%s", formatted)
				}
			case cidr.TypeHex:
				if strings.Contains(formatted, "Hexadecimal:    ") {
					t.Errorf("expected format output not to repeat Hex, got:\n%s", formatted)
				}
				if !strings.Contains(formatted, "IPv4 Address:") || !strings.Contains(formatted, "Integer:") || !strings.Contains(formatted, "Binary:") {
					t.Errorf("expected other types in output, got:\n%s", formatted)
				}
			case cidr.TypeBinary:
				if strings.Contains(formatted, "Binary:         ") {
					t.Errorf("expected format output not to repeat Binary, got:\n%s", formatted)
				}
				if !strings.Contains(formatted, "IPv4 Address:") || !strings.Contains(formatted, "Integer:") || !strings.Contains(formatted, "Hexadecimal:") {
					t.Errorf("expected other types in output, got:\n%s", formatted)
				}
			}
		})
	}
}
