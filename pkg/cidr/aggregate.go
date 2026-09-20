package cidr

import (
	"fmt"
	"net/netip"
	"sort"
)

// AggregateCIDRs takes an arbitrary list of IP ranges or CIDRs and combines overlapping
// and adjacent blocks into the minimal possible set of optimal CIDR blocks.
func AggregateCIDRs(ranges []IPRange) ([]netip.Prefix, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	var v4Ranges, v6Ranges []IPRange
	for _, r := range ranges {
		if r.Start.Is4() && r.End.Is4() {
			v4Ranges = append(v4Ranges, r)
		} else if r.Start.Is6() && r.End.Is6() {
			v6Ranges = append(v6Ranges, r)
		} else {
			return nil, fmt.Errorf("invalid range with mismatched IP versions: %s - %s", r.Start, r.End)
		}
	}

	mergedV4, err := aggregateV4(v4Ranges)
	if err != nil {
		return nil, err
	}

	mergedV6, err := aggregateV6(v6Ranges)
	if err != nil {
		return nil, err
	}

	return append(mergedV4, mergedV6...), nil
}

func aggregateV4(ranges []IPRange) ([]netip.Prefix, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	type interval struct {
		start uint64
		end   uint64
	}

	intervals := make([]interval, 0, len(ranges))
	for _, r := range ranges {
		sU, err := IPv4ToUint32(r.Start)
		if err != nil {
			return nil, err
		}
		eU, err := IPv4ToUint32(r.End)
		if err != nil {
			return nil, err
		}
		intervals = append(intervals, interval{start: uint64(sU), end: uint64(eU)})
	}

	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start == intervals[j].start {
			return intervals[i].end < intervals[j].end
		}
		return intervals[i].start < intervals[j].start
	})

	// Merge contiguous and overlapping intervals
	merged := []interval{intervals[0]}
	for i := 1; i < len(intervals); i++ {
		last := &merged[len(merged)-1]
		curr := intervals[i]

		// If curr starts within last range or directly adjacent (last.end + 1)
		if curr.start <= last.end+1 {
			if curr.end > last.end {
				last.end = curr.end
			}
		} else {
			merged = append(merged, curr)
		}
	}

	// Decompose each merged interval into optimal CIDR blocks
	var result []netip.Prefix
	for _, m := range merged {
		prefixes, err := RangeToCIDRs(Uint32ToIPv4(uint32(m.start)), Uint32ToIPv4(uint32(m.end)))
		if err != nil {
			return nil, err
		}
		result = append(result, prefixes...)
	}

	return result, nil
}

func aggregateV6(ranges []IPRange) ([]netip.Prefix, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	// Sort V6 ranges by start address
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start.Compare(ranges[j].Start) < 0
	})

	merged := []IPRange{ranges[0]}
	for i := 1; i < len(ranges); i++ {
		last := &merged[len(merged)-1]
		curr := ranges[i]

		// Check adjacency: last.End.Next() == curr.Start or curr.Start <= last.End
		adjacent := false
		if next := last.End.Next(); next.IsValid() && next.Compare(curr.Start) >= 0 {
			adjacent = true
		}

		if curr.Start.Compare(last.End) <= 0 || adjacent {
			if curr.End.Compare(last.End) > 0 {
				last.End = curr.End
			}
		} else {
			merged = append(merged, curr)
		}
	}

	var result []netip.Prefix
	for _, m := range merged {
		prefixes, err := RangeToCIDRsV6(m.Start, m.End)
		if err != nil {
			return nil, err
		}
		result = append(result, prefixes...)
	}

	return result, nil
}
