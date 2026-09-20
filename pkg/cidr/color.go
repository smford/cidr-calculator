package cidr

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI escape sequences
const (
	colorReset   = "\033[0m"
	colorCyan    = "\033[36m"
	colorYellow  = "\033[33m"
	colorGreen   = "\033[32m"
	colorBold    = "\033[1m"
	colorMagenta = "\033[35m"
)

// IsTTY checks if the writer is an interactive terminal and not redirected.
func IsTTY(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// ColorizeBinary highlights the network bits in cyan and the host bits in yellow.
func ColorizeBinary(binaryStr string, prefixBits int) string {
	if prefixBits <= 0 || prefixBits > 32 {
		return binaryStr
	}

	var sb strings.Builder
	bitCount := 0
	inHost := false

	for i := 0; i < len(binaryStr); i++ {
		c := binaryStr[i]
		if c == '0' || c == '1' {
			if bitCount == 0 {
				sb.WriteString(colorCyan) // Start network bits
			}
			if bitCount == prefixBits {
				sb.WriteString(colorReset + colorYellow) // Start host bits
				inHost = true
			}
			sb.WriteByte(c)
			bitCount++
		} else {
			sb.WriteByte(c)
		}
	}

	if inHost || bitCount > 0 {
		sb.WriteString(colorReset)
	}

	return sb.String()
}

// FormatBinaryLegend returns an informative color legend for bitmask breakdowns.
func FormatBinaryLegend() string {
	return fmt.Sprintf("%s■ Network Bits%s  %s■ Host Bits%s",
		colorCyan, colorReset, colorYellow, colorReset)
}
