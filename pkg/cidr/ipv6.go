package cidr

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
)

var (
	// ErrIPv6StartGreaterThanEnd indicates start IPv6 exceeds end IPv6.
	ErrIPv6StartGreaterThanEnd = errors.New("start IPv6 cannot be greater than end IPv6")
)

// RangeToCIDRsV6 converts an IPv6 address range [start, end] into the minimal set of CIDR prefixes.
func RangeToCIDRsV6(start, end netip.Addr) ([]netip.Prefix, error) {
	if !start.IsValid() || !end.IsValid() {
		return nil, ErrInvalidIP
	}
	if !start.Is6() || !end.Is6() {
		return nil, errors.New("both start and end must be valid IPv6 addresses")
	}
	if start.Compare(end) > 0 {
		return nil, fmt.Errorf("%w: %s > %s", ErrIPv6StartGreaterThanEnd, start, end)
	}

	startBytes := start.As16()
	endBytes := end.As16()

	cur := new(big.Int).SetBytes(startBytes[:])
	target := new(big.Int).SetBytes(endBytes[:])

	one := big.NewInt(1)
	var prefixes []netip.Prefix

	for cur.Cmp(target) <= 0 {
		// Maximum power-of-two bits aligned with cur
		var maxBits uint
		if cur.Sign() == 0 {
			maxBits = 128
		} else {
			maxBits = cur.TrailingZeroBits()
			if maxBits > 128 {
				maxBits = 128
			}
		}

		// Maximum size constrained by remaining count: target - cur + 1
		remaining := new(big.Int).Sub(target, cur)
		remaining.Add(remaining, one)

		remBits := uint(remaining.BitLen() - 1)
		if remBits < maxBits {
			maxBits = remBits
		}

		prefixLen := int(128 - maxBits)

		// Convert cur back to 16 bytes
		curBytes := cur.Bytes()
		var ip16 [16]byte
		copy(ip16[16-len(curBytes):], curBytes)

		addr := netip.AddrFrom16(ip16)
		prefixes = append(prefixes, netip.PrefixFrom(addr, prefixLen))

		// cur += (1 << maxBits)
		blockSize := new(big.Int).Lsh(one, maxBits)
		cur.Add(cur, blockSize)
	}

	return prefixes, nil
}

// RangeToCIDRsAny handles both IPv4 and IPv6 address ranges.
func RangeToCIDRsAny(start, end netip.Addr) ([]netip.Prefix, error) {
	if !start.IsValid() || !end.IsValid() {
		return nil, ErrInvalidIP
	}
	if start.Is4() && end.Is4() {
		return RangeToCIDRs(start, end)
	}
	if start.Is6() && end.Is6() {
		return RangeToCIDRsV6(start, end)
	}
	return nil, fmt.Errorf("mismatched IP versions: start is IPv%d and end is IPv%d",
		ipVersion(start), ipVersion(end))
}

func ipVersion(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	if addr.Is6() {
		return 6
	}
	return 0
}
