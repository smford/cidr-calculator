package cidr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
)

var (
	// ErrInvalidIP indicates that the provided IP address is invalid.
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrIPv6NotSupported indicates that an IPv6 address was provided when only IPv4 is supported.
	ErrIPv6NotSupported = errors.New("only IPv4 addresses are supported")
	// ErrStartGreaterThanEnd indicates that the start IP address exceeds the end IP address.
	ErrStartGreaterThanEnd = errors.New("start IP cannot be greater than end IP")
)

// IPv4ToUint32 converts a netip.Addr (IPv4) to its 32-bit unsigned integer representation.
func IPv4ToUint32(ip netip.Addr) (uint32, error) {
	if !ip.IsValid() {
		return 0, ErrInvalidIP
	}
	if !ip.Is4() {
		return 0, ErrIPv6NotSupported
	}
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}

// Uint32ToIPv4 converts a 32-bit unsigned integer to an IPv4 netip.Addr.
func Uint32ToIPv4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// RangeToCIDRs converts an IPv4 address range [start, end] into the minimal set of CIDR blocks.
func RangeToCIDRs(start, end netip.Addr) ([]netip.Prefix, error) {
	startU32, err := IPv4ToUint32(start)
	if err != nil {
		return nil, fmt.Errorf("invalid start IP %q: %w", start, err)
	}
	endU32, err := IPv4ToUint32(end)
	if err != nil {
		return nil, fmt.Errorf("invalid end IP %q: %w", end, err)
	}

	if startU32 > endU32 {
		return nil, fmt.Errorf("%w: %s > %s", ErrStartGreaterThanEnd, start, end)
	}

	cur := uint64(startU32)
	target := uint64(endU32)

	var prefixes []netip.Prefix

	for cur <= target {
		// Maximum power-of-two block size constrained by alignment
		var maxBits uint8
		if cur == 0 {
			maxBits = 32
		} else {
			maxBits = uint8(bits.TrailingZeros32(uint32(cur)))
		}

		// Maximum power-of-two block size constrained by remaining count
		remaining := target - cur + 1
		remBits := uint8(bits.Len64(remaining) - 1)

		if remBits < maxBits {
			maxBits = remBits
		}

		blockSize := uint64(1) << maxBits
		prefixLen := int(32 - maxBits)

		addr := Uint32ToIPv4(uint32(cur))
		prefixes = append(prefixes, netip.PrefixFrom(addr, prefixLen))

		cur += blockSize
	}

	return prefixes, nil
}

// TotalIPs returns the number of IPv4 addresses contained in the range [start, end] inclusive.
func TotalIPs(start, end netip.Addr) (uint64, error) {
	startU32, err := IPv4ToUint32(start)
	if err != nil {
		return 0, err
	}
	endU32, err := IPv4ToUint32(end)
	if err != nil {
		return 0, err
	}
	if startU32 > endU32 {
		return 0, fmt.Errorf("%w: %s > %s", ErrStartGreaterThanEnd, start, end)
	}
	return uint64(endU32) - uint64(startU32) + 1, nil
}

// PrefixIPCount returns the total number of IPv4 addresses in a given prefix.
func PrefixIPCount(prefix netip.Prefix) uint64 {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return 0
	}
	return uint64(1) << (32 - prefix.Bits())
}

// GenerateIPs iterates through all IPv4 addresses in the range [start, end] sequentially,
// invoking the callback fn for each address. Iteration terminates early if fn returns false.
func GenerateIPs(start, end netip.Addr, fn func(netip.Addr) bool) error {
	startU32, err := IPv4ToUint32(start)
	if err != nil {
		return fmt.Errorf("invalid start IP: %w", err)
	}
	endU32, err := IPv4ToUint32(end)
	if err != nil {
		return fmt.Errorf("invalid end IP: %w", err)
	}
	if startU32 > endU32 {
		return fmt.Errorf("%w: %s > %s", ErrStartGreaterThanEnd, start, end)
	}

	cur := uint64(startU32)
	target := uint64(endU32)

	for cur <= target {
		addr := Uint32ToIPv4(uint32(cur))
		if !fn(addr) {
			break
		}
		cur++
	}
	return nil
}

// AllIPs returns a slice of all IPv4 addresses in the range [start, end].
// To protect against excessive memory usage on large ranges, it limits in-memory slice
// allocation to maxInMemory (1,000,000 IPs). For larger ranges, use GenerateIPs for streaming.
func AllIPs(start, end netip.Addr) ([]netip.Addr, error) {
	total, err := TotalIPs(start, end)
	if err != nil {
		return nil, err
	}

	const maxInMemory = 1_000_000
	if total > maxInMemory {
		return nil, fmt.Errorf("range contains %d IP addresses, exceeding in-memory limit of %d", total, maxInMemory)
	}

	ips := make([]netip.Addr, 0, total)
	err = GenerateIPs(start, end, func(addr netip.Addr) bool {
		ips = append(ips, addr)
		return true
	})
	return ips, err
}

// PrefixMask returns the IPv4 netmask netip.Addr for a given prefix length (0-32).
func PrefixMask(bits int) netip.Addr {
	if bits <= 0 {
		return Uint32ToIPv4(0)
	}
	if bits >= 32 {
		return Uint32ToIPv4(0xFFFFFFFF)
	}
	mask := ^uint32(0) << (32 - bits)
	return Uint32ToIPv4(mask)
}

// PrefixWildcard returns the IPv4 wildcard (inverse) mask netip.Addr for a given prefix length.
func PrefixWildcard(bits int) netip.Addr {
	if bits <= 0 {
		return Uint32ToIPv4(0xFFFFFFFF)
	}
	if bits >= 32 {
		return Uint32ToIPv4(0)
	}
	mask := ^uint32(0) << (32 - bits)
	return Uint32ToIPv4(^mask)
}
