package cidr

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
)

// SplitCIDR splits a parent CIDR prefix into smaller subnets of a target prefix length.
func SplitCIDR(parent netip.Prefix, targetBits int) ([]netip.Prefix, error) {
	if !parent.IsValid() {
		return nil, errors.New("invalid parent CIDR")
	}

	maxBits := 32
	if parent.Addr().Is6() {
		maxBits = 128
	}

	if targetBits < parent.Bits() {
		return nil, fmt.Errorf("target prefix /%d is larger than parent prefix /%d", targetBits, parent.Bits())
	}
	if targetBits > maxBits {
		return nil, fmt.Errorf("target prefix /%d exceeds maximum of /%d", targetBits, maxBits)
	}

	bitDiff := targetBits - parent.Bits()
	// Prevent unbounded memory allocation (max 65536 subnets per split)
	if bitDiff > 16 {
		return nil, fmt.Errorf("splitting from /%d to /%d creates %d subnets (limit is 65536)",
			parent.Bits(), targetBits, 1<<bitDiff)
	}

	count := 1 << bitDiff
	result := make([]netip.Prefix, 0, count)

	cur := parent.Masked().Addr()
	for i := 0; i < count; i++ {
		p := netip.PrefixFrom(cur, targetBits)
		result = append(result, p)

		// Move to next subnet
		if cur.Is4() {
			u, _ := IPv4ToUint32(cur)
			subSize := uint32(1) << (32 - targetBits)
			nextU := u + subSize
			cur = Uint32ToIPv4(nextU)
		} else {
			// IPv6 advance
			subSizeBits := 128 - targetBits
			cur = advanceIPv6(cur, subSizeBits)
		}
	}

	return result, nil
}

// SplitCIDRByCount splits a parent CIDR into at least N subnets of equal size.
func SplitCIDRByCount(parent netip.Prefix, subnetCount int) ([]netip.Prefix, error) {
	if subnetCount <= 0 {
		return nil, errors.New("subnet count must be greater than zero")
	}
	if subnetCount == 1 {
		return []netip.Prefix{parent.Masked()}, nil
	}

	// Calculate next power of 2
	neededBits := bits.Len(uint(subnetCount - 1))
	targetBits := parent.Bits() + neededBits

	return SplitCIDR(parent, targetBits)
}

func advanceIPv6(addr netip.Addr, shiftBits int) netip.Addr {
	b := addr.As16()
	// Add 1 << shiftBits to 16-byte big-endian number
	byteIdx := 15 - (shiftBits / 8)
	bitOffset := shiftBits % 8
	var carry uint16 = 1 << bitOffset

	for i := byteIdx; i >= 0 && carry > 0; i-- {
		sum := uint16(b[i]) + carry
		b[i] = byte(sum)
		carry = sum >> 8
	}
	return netip.AddrFrom16(b)
}
