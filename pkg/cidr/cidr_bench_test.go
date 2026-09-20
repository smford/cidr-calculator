package cidr_test

import (
	"testing"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

func BenchmarkRangeToCIDRs_Small(b *testing.B) {
	start := mustAddr("192.168.1.10")
	end := mustAddr("192.168.1.20")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cidr.RangeToCIDRs(start, end)
	}
}

func BenchmarkRangeToCIDRs_Large(b *testing.B) {
	start := mustAddr("10.0.0.1")
	end := mustAddr("10.255.255.254")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cidr.RangeToCIDRs(start, end)
	}
}

func BenchmarkParseRange(b *testing.B) {
	s := "192.168.1.10-192.168.1.20"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cidr.ParseRange(s)
	}
}

func BenchmarkConvertIP(b *testing.B) {
	s := "3232235786"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cidr.ConvertIP(s)
	}
}
