package cidr_test

import (
	"strings"
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestGetRangeInfo(t *testing.T) {
	t.Run("private RFC 1918 range with plus syntax", func(t *testing.T) {
		r, err := cidr.ParseRange("192.168.1.10+5")
		if err != nil {
			t.Fatalf("failed to parse range: %v", err)
		}

		info, err := cidr.GetRangeInfo(r)
		if err != nil {
			t.Fatalf("GetRangeInfo error: %v", err)
		}

		if info.TotalIPs != 6 {
			t.Errorf("expected 6 total IPs, got %d", info.TotalIPs)
		}
		if info.CIDRCount != 2 {
			t.Errorf("expected 2 CIDR blocks, got %d", info.CIDRCount)
		}
		if !strings.Contains(info.Scope, "RFC 1918") {
			t.Errorf("expected RFC 1918 scope, got %s", info.Scope)
		}
		if !strings.Contains(info.HistoricalClass, "Class C") {
			t.Errorf("expected Class C, got %s", info.HistoricalClass)
		}

		formatted := info.FormatText()
		if !strings.Contains(formatted, "IP Range Analysis & Details") {
			t.Errorf("formatted text missing expected header: %s", formatted)
		}
		if !strings.Contains(formatted, "192.168.1.10/31") {
			t.Errorf("formatted text missing CIDR /31: %s", formatted)
		}
	})

	t.Run("single subnet details", func(t *testing.T) {
		r, err := cidr.ParseRange("10.0.0.0/24")
		if err != nil {
			t.Fatalf("failed to parse range: %v", err)
		}

		info, err := cidr.GetRangeInfo(r)
		if err != nil {
			t.Fatalf("GetRangeInfo error: %v", err)
		}

		if !info.IsSingleSubnet {
			t.Error("expected IsSingleSubnet to be true")
		}
		if info.Netmask != "255.255.255.0" {
			t.Errorf("expected netmask 255.255.255.0, got %s", info.Netmask)
		}
		if info.WildcardMask != "0.0.0.255" {
			t.Errorf("expected wildcard 0.0.0.255, got %s", info.WildcardMask)
		}
		if info.UsableHostsCount != 254 {
			t.Errorf("expected 254 usable hosts, got %d", info.UsableHostsCount)
		}
		if !strings.Contains(info.HistoricalClass, "Class A") {
			t.Errorf("expected Class A, got %s", info.HistoricalClass)
		}
	})

	t.Run("public IP scope", func(t *testing.T) {
		r, err := cidr.ParseRange("8.8.8.8")
		if err != nil {
			t.Fatalf("failed to parse range: %v", err)
		}

		info, err := cidr.GetRangeInfo(r)
		if err != nil {
			t.Fatalf("GetRangeInfo error: %v", err)
		}

		if !strings.Contains(info.Scope, "Public Internet") {
			t.Errorf("expected Public Internet scope, got %s", info.Scope)
		}
	})
}
