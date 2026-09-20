package cidr_test

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestFormatPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}

	// 1. FormatCIDR
	t.Run("FormatCIDR", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatCIDR)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "10.0.0.0/24\n10.0.1.0/24"
		if out != expected {
			t.Errorf("got %q, want %q", out, expected)
		}
	})

	// 2. FormatTerraform
	t.Run("FormatTerraform", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatTerraform)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `["10.0.0.0/24", "10.0.1.0/24"]`
		if out != expected {
			t.Errorf("got %q, want %q", out, expected)
		}
	})

	// 3. FormatTF shorthand
	t.Run("FormatTF", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatTF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `["10.0.0.0/24", "10.0.1.0/24"]`
		if out != expected {
			t.Errorf("got %q, want %q", out, expected)
		}
	})

	// 4. FormatCSV
	t.Run("FormatCSV", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatCSV)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 3 {
			t.Fatalf("expected 3 lines, got %d: %q", len(lines), out)
		}
		if lines[0] != "cidr,start_ip,end_ip,count" {
			t.Errorf("unexpected header: %s", lines[0])
		}
		if lines[1] != "10.0.0.0/24,10.0.0.0,10.0.0.255,256" {
			t.Errorf("unexpected row 1: %s", lines[1])
		}
		if lines[2] != "10.0.1.0/24,10.0.1.0,10.0.1.255,256" {
			t.Errorf("unexpected row 2: %s", lines[2])
		}
	})

	// 5. FormatAWS
	t.Run("FormatAWS", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatAWS)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var rules []cidr.AWSIngressRule
		if err := json.Unmarshal([]byte(out), &rules); err != nil {
			t.Fatalf("failed to unmarshal AWS rules: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		if rules[0].CidrIP != "10.0.0.0/24" {
			t.Errorf("expected CidrIp 10.0.0.0/24, got %s", rules[0].CidrIP)
		}
	})

	// 6. FormatJSON
	t.Run("FormatJSON", func(t *testing.T) {
		out, err := cidr.FormatPrefixes(prefixes, cidr.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var list []string
		if err := json.Unmarshal([]byte(out), &list); err != nil {
			t.Fatalf("failed to unmarshal JSON list: %v", err)
		}
		if len(list) != 2 || list[0] != "10.0.0.0/24" || list[1] != "10.0.1.0/24" {
			t.Errorf("unexpected JSON list: %v", list)
		}
	})

	// 7. Unsupported format
	t.Run("UnsupportedFormat", func(t *testing.T) {
		_, err := cidr.FormatPrefixes(prefixes, "yaml")
		if err == nil {
			t.Errorf("expected error for unsupported format, got nil")
		}
	})
}
