package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/smford/cidr-calculator/pkg/cidr"
)

// Build information injected via ldflags during build.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		if Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
		if Commit == "none" {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					if len(setting.Value) > 7 {
						Commit = setting.Value[:7]
					} else {
						Commit = setting.Value
					}
				}
				if setting.Key == "vcs.time" && BuildDate == "unknown" {
					BuildDate = setting.Value
				}
			}
		}
	}
}

// RangeResult contains the calculated CIDR data for a given range.
type RangeResult struct {
	Range     string          `json:"range"`
	StartIP   string          `json:"start_ip"`
	EndIP     string          `json:"end_ip"`
	TotalIPs  uint64          `json:"total_ips"`
	CIDRCount int             `json:"cidr_count,omitempty"`
	CIDRs     []string        `json:"cidrs,omitempty"`
	IPs       []string        `json:"ips,omitempty"`
	Info      *cidr.RangeInfo `json:"info,omitempty"`
}

// Run executes the CLI with the provided arguments and streams.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var (
		showAll   bool
		showInfo  bool
		noCIDR    bool
		subcmd    string
		cleanArgs []string
	)

	// Pre-filter positional keywords or flag styles
	for _, arg := range args {
		switch strings.ToLower(strings.TrimSpace(arg)) {
		case "all", "-all", "--all":
			showAll = true
		case "info", "-info", "--info":
			showInfo = true
		case "nocidr", "-nocidr", "--nocidr":
			noCIDR = true
		case "convert", "-convert", "--convert":
			if subcmd == "" {
				subcmd = "convert"
			}
		case "aggregate", "merge", "-aggregate", "--aggregate":
			if subcmd == "" {
				subcmd = "aggregate"
			}
		case "overlap", "-overlap", "--overlap":
			if subcmd == "" {
				subcmd = "overlap"
			}
		case "contains", "-contains", "--contains":
			if subcmd == "" {
				subcmd = "contains"
			}
		case "exclude", "-exclude", "--exclude":
			if subcmd == "" {
				subcmd = "exclude"
			}
		case "split", "subnet", "-split", "--split":
			if subcmd == "" {
				subcmd = "split"
			}
		case "completion", "-completion", "--completion":
			if subcmd == "" {
				subcmd = "completion"
			}
		default:
			cleanArgs = append(cleanArgs, arg)
		}
	}

	fs := flag.NewFlagSet("cidr-calculator", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		jsonOutput  bool
		formatStr   string
		summary     bool
		showVersion bool
		showHelp    bool
	)

	fs.BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	fs.StringVar(&formatStr, "format", "", "Output format: cidr, json, terraform (or tf), csv, aws")
	fs.BoolVar(&summary, "s", false, "Print summary with total IPs and CIDR count (shorthand)")
	fs.BoolVar(&summary, "summary", false, "Print summary with total IPs and CIDR count")
	fs.BoolVar(&showVersion, "v", false, "Print version information (shorthand)")
	fs.BoolVar(&showVersion, "version", false, "Print version information")
	fs.BoolVar(&showHelp, "h", false, "Show help message (shorthand)")
	fs.BoolVar(&showHelp, "help", false, "Show help message")

	fs.Usage = func() {
		printUsage(stderr)
	}

	if err := fs.Parse(cleanArgs); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if showHelp {
		printUsage(stdout)
		return 0
	}

	if showVersion {
		fmt.Fprintf(stdout, "cidr-calculator %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		return 0
	}

	posArgs := fs.Args()

	// Normalize output format
	outFormat := cidr.OutputFormat(formatStr)
	if jsonOutput && outFormat == "" {
		outFormat = cidr.FormatJSON
	}
	if outFormat == "" {
		outFormat = cidr.FormatCIDR
	}

	// Dispatch subcommands
	switch subcmd {
	case "completion":
		shell := "bash"
		if len(posArgs) > 0 {
			shell = posArgs[0]
		}
		if err := GenerateCompletion(shell, stdout); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 0

	case "convert":
		return runConvert(posArgs, stdin, stdout, stderr, outFormat == cidr.FormatJSON)

	case "aggregate":
		return runAggregate(posArgs, stdin, stdout, stderr, outFormat)

	case "overlap":
		return runOverlap(posArgs, stdout, stderr, outFormat == cidr.FormatJSON)

	case "contains":
		return runContains(posArgs, stdout, stderr, outFormat == cidr.FormatJSON)

	case "exclude":
		return runExclude(posArgs, stdout, stderr, outFormat)

	case "split":
		return runSplit(posArgs, stdout, stderr, outFormat)
	}

	// Default mode: Range-to-CIDR conversion
	var rawInputs []string
	readStdin := false
	if len(posArgs) == 1 && posArgs[0] == "-" {
		readStdin = true
	} else if len(posArgs) == 0 {
		if isStdinPiped(stdin) {
			readStdin = true
		} else {
			printUsage(stderr)
			return 1
		}
	}

	if readStdin {
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rawInputs = append(rawInputs, line)
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(stderr, "Error reading from standard input: %v\n", err)
			return 1
		}
		if len(rawInputs) == 0 {
			fmt.Fprintf(stderr, "Error: no IP ranges provided via standard input\n")
			return 1
		}
	} else {
		rawInputs = posArgs
	}

	var parsedRanges []cidr.IPRange
	if readStdin {
		for _, line := range rawInputs {
			r, err := cidr.ParseRange(line)
			if err != nil {
				fmt.Fprintf(stderr, "Error parsing range %q: %v\n", line, err)
				return 1
			}
			parsedRanges = append(parsedRanges, r)
		}
	} else {
		ranges, err := cidr.ParseArgs(rawInputs)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		parsedRanges = ranges
	}

	var results []RangeResult
	var allPrefixes []netip.Prefix
	var totalAllIPs uint64
	var totalAllCIDRs int

	for _, r := range parsedRanges {
		var totalIPs uint64
		if r.Start.Is4() {
			tIPs, err := cidr.TotalIPs(r.Start, r.End)
			if err != nil {
				fmt.Fprintf(stderr, "Error calculating total IPs: %v\n", err)
				return 1
			}
			totalIPs = tIPs
		}
		totalAllIPs += totalIPs

		rawDesc := r.Raw
		if rawDesc == "" {
			rawDesc = fmt.Sprintf("%s-%s", r.Start, r.End)
		}

		res := RangeResult{
			Range:    rawDesc,
			StartIP:  r.Start.String(),
			EndIP:    r.End.String(),
			TotalIPs: totalIPs,
		}

		if !noCIDR {
			prefixes, err := cidr.RangeToCIDRsAny(r.Start, r.End)
			if err != nil {
				fmt.Fprintf(stderr, "Error converting range %s to CIDRs: %v\n", r.Raw, err)
				return 1
			}
			res.CIDRCount = len(prefixes)
			totalAllCIDRs += len(prefixes)
			allPrefixes = append(allPrefixes, prefixes...)
			res.CIDRs = make([]string, len(prefixes))
			for i, p := range prefixes {
				res.CIDRs[i] = p.String()
			}
		}

		if showInfo && r.Start.Is4() {
			info, err := cidr.GetRangeInfo(r)
			if err != nil {
				fmt.Fprintf(stderr, "Error generating info for range %s: %v\n", r.Raw, err)
				return 1
			}
			res.Info = &info
		}

		if showAll || noCIDR {
			if outFormat == cidr.FormatJSON && r.Start.Is4() {
				ips, err := cidr.AllIPs(r.Start, r.End)
				if err != nil {
					fmt.Fprintf(stderr, "Error generating IP list: %v\n", err)
					return 1
				}
				res.IPs = make([]string, len(ips))
				for i, ip := range ips {
					res.IPs[i] = ip.String()
				}
			}
		}

		results = append(results, res)
	}

	// Output Formatting
	if formatStr != "" && !showAll && !noCIDR && !showInfo {
		formatted, err := cidr.FormatPrefixes(allPrefixes, outFormat)
		if err != nil {
			fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, formatted)
		return 0
	}

	if outFormat == cidr.FormatJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		var outData any = results
		if len(results) == 1 {
			outData = results[0]
		}
		if err := enc.Encode(outData); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON: %v\n", err)
			return 1
		}
		return 0
	}

	// Default Text Mode
	isTty := cidr.IsTTY(stdout)
	for i, res := range results {
		r := parsedRanges[i]

		if showInfo && res.Info != nil {
			fmt.Fprintln(stdout, res.Info.FormatTextWithColor(isTty))
		}

		if !noCIDR && !showInfo {
			for _, c := range res.CIDRs {
				fmt.Fprintln(stdout, c)
			}
		}

		if showAll || noCIDR {
			if r.Start.Is4() {
				err := cidr.GenerateIPs(r.Start, r.End, func(addr netip.Addr) bool {
					fmt.Fprintln(stdout, addr)
					return true
				})
				if err != nil {
					fmt.Fprintf(stderr, "Error printing IP addresses: %v\n", err)
					return 1
				}
			} else {
				// IPv6 single or small range output
				cur := r.Start
				for {
					fmt.Fprintln(stdout, cur)
					if cur == r.End {
						break
					}
					next := cur.Next()
					if !next.IsValid() || next.Compare(r.End) > 0 {
						break
					}
					cur = next
				}
			}
		}
	}

	if summary {
		if len(results) == 1 {
			if noCIDR {
				fmt.Fprintf(stderr, "\nSummary: %d IP address(es) for range %s\n",
					results[0].TotalIPs, results[0].Range)
			} else {
				fmt.Fprintf(stderr, "\nSummary: %d CIDR block(s) covering %d IP address(es) for range %s\n",
					results[0].CIDRCount, results[0].TotalIPs, results[0].Range)
			}
		} else {
			if noCIDR {
				fmt.Fprintf(stderr, "\nSummary: %d IP address(es) across %d range(s)\n",
					totalAllIPs, len(results))
			} else {
				fmt.Fprintf(stderr, "\nSummary: %d CIDR block(s) covering %d IP address(es) across %d range(s)\n",
					totalAllCIDRs, totalAllIPs, len(results))
			}
		}
	}

	return 0
}

func runAggregate(posArgs []string, stdin io.Reader, stdout, stderr io.Writer, format cidr.OutputFormat) int {
	var rawInputs []string
	if len(posArgs) == 0 || (len(posArgs) == 1 && posArgs[0] == "-") {
		if !isStdinPiped(stdin) && len(posArgs) == 0 {
			fmt.Fprintln(stderr, "Error: aggregate requires at least one CIDR block or range")
			return 1
		}
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rawInputs = append(rawInputs, line)
		}
	} else {
		rawInputs = posArgs
	}

	var ranges []cidr.IPRange
	for _, raw := range rawInputs {
		r, err := cidr.ParseRange(raw)
		if err != nil {
			fmt.Fprintf(stderr, "Error parsing range %q: %v\n", raw, err)
			return 1
		}
		ranges = append(ranges, r)
	}

	prefixes, err := cidr.AggregateCIDRs(ranges)
	if err != nil {
		fmt.Fprintf(stderr, "Error aggregating CIDRs: %v\n", err)
		return 1
	}

	formatted, err := cidr.FormatPrefixes(prefixes, format)
	if err != nil {
		fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, formatted)
	return 0
}

func runOverlap(posArgs []string, stdout, stderr io.Writer, jsonOutput bool) int {
	if len(posArgs) < 2 {
		fmt.Fprintln(stderr, "Error: overlap requires two IP ranges or CIDRs to compare")
		return 2
	}

	r1, err := cidr.ParseRange(posArgs[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing first range %q: %v\n", posArgs[0], err)
		return 2
	}
	r2, err := cidr.ParseRange(posArgs[1])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing second range %q: %v\n", posArgs[1], err)
		return 2
	}

	res, err := cidr.CheckOverlap(r1, r2)
	if err != nil {
		fmt.Fprintf(stderr, "Error checking overlap: %v\n", err)
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.Overlaps {
			return 1
		}
		return 0
	}

	if res.Overlaps {
		fmt.Fprintf(stdout, "OVERLAP DETECTED: %s overlaps with %s\n", res.RangeA, res.RangeB)
		if res.Intersection != nil {
			fmt.Fprintf(stdout, "Intersection:     %s - %s\n", res.Intersection.Start, res.Intersection.End)
			if len(res.CIDRs) > 0 {
				fmt.Fprintln(stdout, "CIDR Blocks:")
				for _, c := range res.CIDRs {
					fmt.Fprintf(stdout, "  %s\n", c)
				}
			}
		}
		return 1
	}

	fmt.Fprintf(stdout, "NO OVERLAP: %s does not overlap with %s\n", res.RangeA, res.RangeB)
	return 0
}

func runContains(posArgs []string, stdout, stderr io.Writer, jsonOutput bool) int {
	if len(posArgs) < 2 {
		fmt.Fprintln(stderr, "Error: contains requires container range and target IP/range")
		return 2
	}

	container, err := cidr.ParseRange(posArgs[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing container range %q: %v\n", posArgs[0], err)
		return 2
	}
	target, err := cidr.ParseRange(posArgs[1])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing target %q: %v\n", posArgs[1], err)
		return 2
	}

	ok := cidr.Contains(container, target)

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"container": posArgs[0],
			"target":    posArgs[1],
			"contains":  ok,
		})
		if ok {
			return 0
		}
		return 1
	}

	if ok {
		fmt.Fprintf(stdout, "YES: %s contains %s\n", posArgs[0], posArgs[1])
		return 0
	}

	fmt.Fprintf(stdout, "NO: %s does not contain %s\n", posArgs[0], posArgs[1])
	return 1
}

func runExclude(posArgs []string, stdout, stderr io.Writer, format cidr.OutputFormat) int {
	if len(posArgs) < 2 {
		fmt.Fprintln(stderr, "Error: exclude requires a base range followed by at least one range to exclude")
		return 2
	}

	base, err := cidr.ParseRange(posArgs[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing base range %q: %v\n", posArgs[0], err)
		return 2
	}

	var exclusions []cidr.IPRange
	for _, exclStr := range posArgs[1:] {
		r, err := cidr.ParseRange(exclStr)
		if err != nil {
			fmt.Fprintf(stderr, "Error parsing exclusion %q: %v\n", exclStr, err)
			return 2
		}
		exclusions = append(exclusions, r)
	}

	prefixes, err := cidr.ExcludeRanges(base, exclusions)
	if err != nil {
		fmt.Fprintf(stderr, "Error excluding ranges: %v\n", err)
		return 1
	}

	formatted, err := cidr.FormatPrefixes(prefixes, format)
	if err != nil {
		fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, formatted)
	return 0
}

func runSplit(posArgs []string, stdout, stderr io.Writer, format cidr.OutputFormat) int {
	if len(posArgs) < 2 {
		fmt.Fprintln(stderr, "Error: split requires a parent CIDR and target prefix (e.g. /24) or subnet count")
		return 2
	}

	parent, err := netip.ParsePrefix(posArgs[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing parent CIDR %q: %v\n", posArgs[0], err)
		return 2
	}

	targetStr := posArgs[1]
	var prefixes []netip.Prefix

	if strings.HasPrefix(targetStr, "/") {
		bits, err := strconv.Atoi(targetStr[1:])
		if err != nil {
			fmt.Fprintf(stderr, "Invalid target prefix length %q: %v\n", targetStr, err)
			return 2
		}
		p, err := cidr.SplitCIDR(parent, bits)
		if err != nil {
			fmt.Fprintf(stderr, "Error splitting CIDR: %v\n", err)
			return 1
		}
		prefixes = p
	} else {
		val, err := strconv.Atoi(targetStr)
		if err != nil {
			fmt.Fprintf(stderr, "Invalid target subnet specification %q: %v\n", targetStr, err)
			return 2
		}
		// If val is greater than parent prefix bits and <= 32/128, treat as prefix length, else count
		maxBits := 32
		if parent.Addr().Is6() {
			maxBits = 128
		}
		if val > parent.Bits() && val <= maxBits {
			p, err := cidr.SplitCIDR(parent, val)
			if err != nil {
				fmt.Fprintf(stderr, "Error splitting CIDR: %v\n", err)
				return 1
			}
			prefixes = p
		} else {
			p, err := cidr.SplitCIDRByCount(parent, val)
			if err != nil {
				fmt.Fprintf(stderr, "Error splitting CIDR: %v\n", err)
				return 1
			}
			prefixes = p
		}
	}

	formatted, err := cidr.FormatPrefixes(prefixes, format)
	if err != nil {
		fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, formatted)
	return 0
}

func runConvert(posArgs []string, stdin io.Reader, stdout, stderr io.Writer, jsonOutput bool) int {
	var rawInputs []string
	readStdin := false

	if len(posArgs) == 1 && posArgs[0] == "-" {
		readStdin = true
	} else if len(posArgs) == 0 {
		if isStdinPiped(stdin) {
			readStdin = true
		} else {
			fmt.Fprintln(stderr, "Error: convert requires an IPv4 address in integer, hex, binary, or dotted decimal format")
			return 1
		}
	} else {
		rawInputs = posArgs
	}

	if readStdin {
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rawInputs = append(rawInputs, line)
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(stderr, "Error reading standard input: %v\n", err)
			return 1
		}
		if len(rawInputs) == 0 {
			fmt.Fprintln(stderr, "Error: no input provided via standard input")
			return 1
		}
	}

	var results []cidr.ConversionResult
	for _, raw := range rawInputs {
		res, err := cidr.ConvertIP(raw)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		results = append(results, res)
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		var outData any = results
		if len(results) == 1 {
			outData = results[0]
		}
		if err := enc.Encode(outData); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON: %v\n", err)
			return 1
		}
		return 0
	}

	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprintln(stdout, res.FormatText())
	}

	return 0
}

func isStdinPiped(r io.Reader) bool {
	if r == nil {
		return false
	}
	file, ok := r.(*os.File)
	if !ok {
		return true
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `cidr-calculator converts IPv4/IPv6 address ranges into minimal CIDR blocks and provides network intelligence.

USAGE:
    cidr-calculator [flags] [options] <ip-range>
    cidr-calculator [flags] [options] <start-ip> <end-ip>
    cidr-calculator [flags] [options] <start-ip> - <end-ip>
    cidr-calculator [flags] [options] <base-ip>+<count>
    cidr-calculator <subcommand> [args...]
    cat ranges.txt | cidr-calculator [flags] [options]

SUBCOMMANDS:
    convert     Convert IPv4 between integer, hex, binary, and dotted decimal
    aggregate   Merge adjacent and overlapping CIDR blocks into minimal supersets
    overlap     Detect IP address collision/intersection between two ranges
    contains    Check if a parent range completely encloses a target range
    exclude     Subtract excluded IP ranges from a base range
    split       Subdivide a parent CIDR into smaller subnets (by prefix or count)
    completion  Generate shell autocompletion script (bash, zsh, fish)

ARGUMENTS & OPTIONS:
    all         Print out a list of all IP addresses in the range
    nocidr      Suppress CIDR output and only print the list of IP addresses
    info        Print detailed diagnostic, architectural, and subnet analysis

EXAMPLES:
    # Basic range to minimal CIDR blocks:
    cidr-calculator 192.168.1.10-192.168.1.20

    # Plus offset notation (base IP + 5):
    cidr-calculator 192.168.1.10+5

    # Terraform IaC format output:
    cidr-calculator -format=terraform 192.168.1.10+5

    # AWS Security Group Ingress JSON:
    cidr-calculator -format=aws 192.168.1.10+5

    # Merge overlapping/adjacent CIDRs:
    cidr-calculator aggregate 10.0.0.0/24 10.0.1.0/24 10.0.0.128/25

    # Detect collisions / overlapping subnets:
    cidr-calculator overlap 10.100.0.0/16 10.100.32.0/20

    # Check if subnet contains an IP:
    cidr-calculator contains 10.0.0.0/16 10.0.5.1

    # Carve out / exclude gateway and DHCP addresses:
    cidr-calculator exclude 192.168.1.0/24 192.168.1.1 192.168.1.100-192.168.1.150

    # Split parent CIDR into /24 subnets:
    cidr-calculator split 10.0.0.0/22 /24

    # Convert integer, hex, or binary formats:
    cidr-calculator convert 3232235786
    cidr-calculator convert 0xC0A8010A

FLAGS:
    -format=...   Output preset: cidr (default), json, terraform (tf), csv, aws
    -json         Output result in structured JSON format
    -s, -summary  Print summary statistics (total IPs and CIDR block count)
    -v, -version  Print version information
    -h, -help     Print this help message`)
}
