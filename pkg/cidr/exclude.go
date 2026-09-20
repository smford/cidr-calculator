package cidr

import (
	"errors"
	"fmt"
	"net/netip"
)

// ExcludeRanges subtracts one or more exclusion ranges from a base range, returning
// the minimal set of CIDR blocks representing the remaining address space.
func ExcludeRanges(base IPRange, exclusions []IPRange) ([]netip.Prefix, error) {
	if !base.Start.IsValid() || !base.End.IsValid() {
		return nil, ErrInvalidIP
	}

	remaining := []IPRange{base}

	for _, excl := range exclusions {
		if !excl.Start.IsValid() || !excl.End.IsValid() {
			return nil, ErrInvalidIP
		}
		if excl.Start.Is4() != base.Start.Is4() {
			return nil, errors.New("cannot mix IPv4 and IPv6 in range exclusion")
		}

		var nextRemaining []IPRange
		for _, cur := range remaining {
			sub, err := subtractRange(cur, excl)
			if err != nil {
				return nil, err
			}
			nextRemaining = append(nextRemaining, sub...)
		}
		remaining = nextRemaining
	}

	var result []netip.Prefix
	for _, r := range remaining {
		prefixes, err := RangeToCIDRsAny(r.Start, r.End)
		if err != nil {
			return nil, err
		}
		result = append(result, prefixes...)
	}

	return result, nil
}

func subtractRange(base, excl IPRange) ([]IPRange, error) {
	// No overlap: return original base
	if excl.Start.Compare(base.End) > 0 || excl.End.Compare(base.Start) < 0 {
		return []IPRange{base}, nil
	}

	var res []IPRange

	// Left remnant: base.Start <= X < excl.Start
	if base.Start.Compare(excl.Start) < 0 {
		prev := excl.Start.Prev()
		if prev.IsValid() && prev.Compare(base.Start) >= 0 {
			res = append(res, IPRange{
				Raw:   fmt.Sprintf("%s-%s", base.Start, prev),
				Start: base.Start,
				End:   prev,
			})
		}
	}

	// Right remnant: excl.End < X <= base.End
	if base.End.Compare(excl.End) > 0 {
		next := excl.End.Next()
		if next.IsValid() && next.Compare(base.End) <= 0 {
			res = append(res, IPRange{
				Raw:   fmt.Sprintf("%s-%s", next, base.End),
				Start: next,
				End:   base.End,
			})
		}
	}

	return res, nil
}
