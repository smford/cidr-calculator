package cidr

import (
	"errors"
	"fmt"
)

// OverlapResult describes a detected collision between two IP ranges.
type OverlapResult struct {
	RangeA       string   `json:"range_a"`
	RangeB       string   `json:"range_b"`
	Overlaps     bool     `json:"overlaps"`
	Intersection *IPRange `json:"intersection,omitempty"`
	CIDRs        []string `json:"cidrs,omitempty"`
}

// CheckOverlap determines if two IP ranges intersect and calculates the intersecting interval.
func CheckOverlap(r1, r2 IPRange) (OverlapResult, error) {
	if !r1.Start.IsValid() || !r2.Start.IsValid() {
		return OverlapResult{}, ErrInvalidIP
	}
	if (r1.Start.Is4() != r2.Start.Is4()) || (r1.Start.Is6() != r2.Start.Is6()) {
		return OverlapResult{}, errors.New("cannot compare IPv4 and IPv6 ranges for overlap")
	}

	res := OverlapResult{
		RangeA: r1.Raw,
		RangeB: r2.Raw,
	}
	if res.RangeA == "" {
		res.RangeA = fmt.Sprintf("%s-%s", r1.Start, r1.End)
	}
	if res.RangeB == "" {
		res.RangeB = fmt.Sprintf("%s-%s", r2.Start, r2.End)
	}

	// Overlap condition: r1.Start <= r2.End && r2.Start <= r1.End
	if r1.Start.Compare(r2.End) <= 0 && r2.Start.Compare(r1.End) <= 0 {
		res.Overlaps = true

		// Intersection start = max(r1.Start, r2.Start)
		intStart := r1.Start
		if r2.Start.Compare(intStart) > 0 {
			intStart = r2.Start
		}

		// Intersection end = min(r1.End, r2.End)
		intEnd := r1.End
		if r2.End.Compare(intEnd) < 0 {
			intEnd = r2.End
		}

		intersection := IPRange{
			Raw:   fmt.Sprintf("%s-%s", intStart, intEnd),
			Start: intStart,
			End:   intEnd,
		}
		res.Intersection = &intersection

		prefixes, err := RangeToCIDRsAny(intStart, intEnd)
		if err == nil {
			for _, p := range prefixes {
				res.CIDRs = append(res.CIDRs, p.String())
			}
		}
	}

	return res, nil
}

// Contains checks if the container range completely encloses the target range.
func Contains(container, target IPRange) bool {
	if !container.Start.IsValid() || !target.Start.IsValid() {
		return false
	}
	if (container.Start.Is4() != target.Start.Is4()) || (container.Start.Is6() != target.Start.Is6()) {
		return false
	}
	return container.Start.Compare(target.Start) <= 0 && container.End.Compare(target.End) >= 0
}
