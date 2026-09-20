package cidr

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// InputType identifies the format of the provided IPv4 address representation.
type InputType string

const (
	TypeInteger       InputType = "Integer"
	TypeHex           InputType = "Hexadecimal"
	TypeBinary        InputType = "Binary"
	TypeDottedDecimal InputType = "IPv4 Dotted Decimal"
)

// ConversionResult contains all representations of an IPv4 address.
type ConversionResult struct {
	Input       string    `json:"input"`
	InputType   InputType `json:"input_type"`
	IPv4        string    `json:"ipv4"`
	Integer     uint32    `json:"integer"`
	Hex         string    `json:"hex"`
	Binary      string    `json:"binary"`
	BinaryPlain string    `json:"binary_plain"`
}

// ConvertIP parses an IPv4 address provided in integer, hex, binary, or dotted-decimal
// format and returns a ConversionResult containing all alternate representations.
func ConvertIP(raw string) (ConversionResult, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ConversionResult{}, fmt.Errorf("empty input provided for conversion")
	}

	lower := strings.ToLower(s)

	// 1. Hexadecimal with 0x prefix
	if strings.HasPrefix(lower, "0x") {
		val, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return ConversionResult{}, fmt.Errorf("invalid hexadecimal IPv4 %q: %w", s, err)
		}
		if val > 0xFFFFFFFF {
			return ConversionResult{}, fmt.Errorf("hexadecimal value %q exceeds 32-bit IPv4 space", s)
		}
		return buildConversionResult(s, TypeHex, uint32(val)), nil
	}

	// 2. Binary with 0b prefix
	if strings.HasPrefix(lower, "0b") {
		val, err := strconv.ParseUint(s[2:], 2, 64)
		if err != nil {
			return ConversionResult{}, fmt.Errorf("invalid binary IPv4 %q: %w", s, err)
		}
		if val > 0xFFFFFFFF {
			return ConversionResult{}, fmt.Errorf("binary value %q exceeds 32-bit IPv4 space", s)
		}
		return buildConversionResult(s, TypeBinary, uint32(val)), nil
	}

	// 3. Dot-separated formats (Dotted Binary or IPv4 Dotted Decimal)
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			// Check if dotted binary: e.g. 11000000.10101000.00000001.00001010
			isDottedBinary := true
			for _, p := range parts {
				if len(p) != 8 || !isAll01(p) {
					isDottedBinary = false
					break
				}
			}
			if isDottedBinary {
				var b [4]byte
				for i, p := range parts {
					bVal, _ := strconv.ParseUint(p, 2, 8)
					b[i] = byte(bVal)
				}
				u := binary.BigEndian.Uint32(b[:])
				return buildConversionResult(s, TypeBinary, u), nil
			}

			// IPv4 Dotted Decimal: e.g. 192.168.1.10
			addr, err := netip.ParseAddr(s)
			if err == nil && addr.Is4() {
				u, _ := IPv4ToUint32(addr)
				return buildConversionResult(s, TypeDottedDecimal, u), nil
			}
		}
	}

	// 4. Raw 32-bit binary string (e.g. 11000000101010000000000100001010)
	if len(s) == 32 && isAll01(s) {
		val, err := strconv.ParseUint(s, 2, 64)
		if err != nil {
			return ConversionResult{}, fmt.Errorf("invalid binary IPv4 %q: %w", s, err)
		}
		return buildConversionResult(s, TypeBinary, uint32(val)), nil
	}

	// 5. Hexadecimal without 0x prefix (contains [a-fA-F] and all hex chars)
	if isHexWithLetters(s) {
		val, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			return ConversionResult{}, fmt.Errorf("invalid hexadecimal IPv4 %q: %w", s, err)
		}
		if val > 0xFFFFFFFF {
			return ConversionResult{}, fmt.Errorf("hexadecimal value %q exceeds 32-bit IPv4 space", s)
		}
		return buildConversionResult(s, TypeHex, uint32(val)), nil
	}

	// 6. Decimal Integer (0 to 4294967295)
	if isAllDigits(s) {
		val, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return ConversionResult{}, fmt.Errorf("invalid decimal integer IPv4 %q: %w", s, err)
		}
		if val > 0xFFFFFFFF {
			return ConversionResult{}, fmt.Errorf("integer value %s exceeds 32-bit IPv4 space (max 4294967295)", s)
		}
		return buildConversionResult(s, TypeInteger, uint32(val)), nil
	}

	return ConversionResult{}, fmt.Errorf("unable to parse %q as an IPv4 address in integer, hex, binary, or dotted-decimal format", s)
}

func buildConversionResult(input string, inType InputType, u uint32) ConversionResult {
	addr := Uint32ToIPv4(u)
	b := addr.As4()
	dottedBin := fmt.Sprintf("%08b.%08b.%08b.%08b", b[0], b[1], b[2], b[3])
	plainBin := fmt.Sprintf("%08b%08b%08b%08b", b[0], b[1], b[2], b[3])
	hexStr := fmt.Sprintf("0x%08X", u)

	return ConversionResult{
		Input:       input,
		InputType:   inType,
		IPv4:        addr.String(),
		Integer:     u,
		Hex:         hexStr,
		Binary:      dottedBin,
		BinaryPlain: plainBin,
	}
}

// FormatText formats the conversion output, displaying the input and all other types.
func (c ConversionResult) FormatText() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Input:          %s (%s)\n", c.Input, c.InputType))
	if c.InputType != TypeDottedDecimal {
		sb.WriteString(fmt.Sprintf("IPv4 Address:   %s\n", c.IPv4))
	}
	if c.InputType != TypeInteger {
		sb.WriteString(fmt.Sprintf("Integer:        %d\n", c.Integer))
	}
	if c.InputType != TypeHex {
		sb.WriteString(fmt.Sprintf("Hexadecimal:    %s\n", c.Hex))
	}
	if c.InputType != TypeBinary {
		sb.WriteString(fmt.Sprintf("Binary:         %s\n", c.Binary))
		sb.WriteString(fmt.Sprintf("Binary (Plain): %s\n", c.BinaryPlain))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func isAll01(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' && s[i] != '1' {
			return false
		}
	}
	return len(s) > 0
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isHexWithLetters(s string) bool {
	hasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			// ok
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			hasLetter = true
		default:
			return false
		}
	}
	return hasLetter && len(s) > 0 && len(s) <= 8
}
