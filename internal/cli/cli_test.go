package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/smford/cidr-calculator/internal/cli"
	"github.com/smford/cidr-calculator/pkg/cidr"
)

func TestRun_SingleRange(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10-192.168.1.20"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expectedLines := []string{
		"192.168.1.10/31",
		"192.168.1.12/30",
		"192.168.1.16/30",
		"192.168.1.20/32",
	}

	actualOutput := strings.TrimSpace(stdout.String())
	actualLines := strings.Split(actualOutput, "\n")

	if len(actualLines) != len(expectedLines) {
		t.Fatalf("expected %d lines, got %d:\n%s", len(expectedLines), len(actualLines), actualOutput)
	}

	for i := range expectedLines {
		if actualLines[i] != expectedLines[i] {
			t.Errorf("line %d: got %q, want %q", i, actualLines[i], expectedLines[i])
		}
	}
}

func TestRun_TwoArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"10.0.0.1", "10.0.0.3"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := "10.0.0.1/32\n10.0.0.2/31"
	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-json", "192.168.1.1-192.168.1.5"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	var res cli.RangeResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v. Output was:\n%s", err, stdout.String())
	}

	if res.StartIP != "192.168.1.1" {
		t.Errorf("start IP: got %s, want 192.168.1.1", res.StartIP)
	}
	if res.EndIP != "192.168.1.5" {
		t.Errorf("end IP: got %s, want 192.168.1.5", res.EndIP)
	}
	if res.TotalIPs != 5 {
		t.Errorf("total IPs: got %d, want 5", res.TotalIPs)
	}
	if res.CIDRCount != 3 {
		t.Errorf("cidr count: got %d, want 3", res.CIDRCount)
	}
}

func TestRun_Summary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-s", "192.168.1.10-192.168.1.20"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Summary: 4 CIDR block(s) covering 11 IP address(es)") {
		t.Errorf("expected summary in stderr, got: %s", stderr.String())
	}
}

func TestRun_StdinPipe(t *testing.T) {
	input := `# Comment line
192.168.1.1-192.168.1.2

10.0.0.1-10.0.0.1
`
	stdin := strings.NewReader(input)
	var stdout, stderr bytes.Buffer

	code := cli.Run([]string{"-"}, stdin, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := "192.168.1.1/32\n192.168.1.2/32\n10.0.0.1/32"
	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-version"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "cidr-calculator") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestRun_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "USAGE:") {
		t.Errorf("expected usage output, got: %s", stdout.String())
	}
}

func TestRun_InvalidInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"invalid-range"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for invalid input, got %d", code)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-unknown-flag"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got %d", code)
	}
}

func TestRun_PlusNotation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10+5"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := "192.168.1.10/31\n192.168.1.12/30"
	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_PlusNotation_All(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10+5", "all"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := strings.Join([]string{
		"192.168.1.10/31",
		"192.168.1.12/30",
		"192.168.1.10",
		"192.168.1.11",
		"192.168.1.12",
		"192.168.1.13",
		"192.168.1.14",
		"192.168.1.15",
	}, "\n")

	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_PlusNotation_NoCIDR(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10+5", "nocidr"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := strings.Join([]string{
		"192.168.1.10",
		"192.168.1.11",
		"192.168.1.12",
		"192.168.1.13",
		"192.168.1.14",
		"192.168.1.15",
	}, "\n")

	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_PlusNotation_AllAndNoCIDR(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10+5", "all", "nocidr"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	expected := strings.Join([]string{
		"192.168.1.10",
		"192.168.1.11",
		"192.168.1.12",
		"192.168.1.13",
		"192.168.1.14",
		"192.168.1.15",
	}, "\n")

	if strings.TrimSpace(stdout.String()) != expected {
		t.Errorf("got %q, want %q", strings.TrimSpace(stdout.String()), expected)
	}
}

func TestRun_Info(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"192.168.1.10+5", "info"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "IP Range Analysis & Details") {
		t.Errorf("expected info report header, got: %s", out)
	}
	if !strings.Contains(out, "Private-Use / Internal (RFC 1918)") {
		t.Errorf("expected RFC 1918 scope, got: %s", out)
	}
	if !strings.Contains(out, "192.168.1.10/31") {
		t.Errorf("expected CIDR /31, got: %s", out)
	}
}

func TestRun_JSONWithAllAndInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-json", "192.168.1.10+5", "all", "info"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	var res cli.RangeResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(res.IPs) != 6 {
		t.Errorf("expected 6 IPs in JSON, got %d", len(res.IPs))
	}
	if res.Info == nil {
		t.Fatal("expected Info object in JSON, got nil")
	}
	if res.Info.TotalIPs != 6 {
		t.Errorf("expected TotalIPs 6 in Info, got %d", res.Info.TotalIPs)
	}
}

func TestRun_ConvertInteger(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"convert", "3232235786"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Input:          3232235786 (Integer)") {
		t.Errorf("expected Input line, got:\n%s", out)
	}
	if !strings.Contains(out, "IPv4 Address:   192.168.1.10") {
		t.Errorf("expected IPv4 line, got:\n%s", out)
	}
	if !strings.Contains(out, "Hexadecimal:    0xC0A8010A") {
		t.Errorf("expected Hex line, got:\n%s", out)
	}
	if !strings.Contains(out, "Binary:         11000000.10101000.00000001.00001010") {
		t.Errorf("expected Binary line, got:\n%s", out)
	}
}

func TestRun_ConvertHex(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"convert", "0xC0A8010A"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Input:          0xC0A8010A (Hexadecimal)") {
		t.Errorf("expected Input line, got:\n%s", out)
	}
	if !strings.Contains(out, "IPv4 Address:   192.168.1.10") {
		t.Errorf("expected IPv4 line, got:\n%s", out)
	}
	if !strings.Contains(out, "Integer:        3232235786") {
		t.Errorf("expected Integer line, got:\n%s", out)
	}
}

func TestRun_ConvertBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"convert", "11000000.10101000.00000001.00001010"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "IPv4 Address:   192.168.1.10") {
		t.Errorf("expected IPv4 line, got:\n%s", out)
	}
	if !strings.Contains(out, "Integer:        3232235786") {
		t.Errorf("expected Integer line, got:\n%s", out)
	}
	if !strings.Contains(out, "Hexadecimal:    0xC0A8010A") {
		t.Errorf("expected Hex line, got:\n%s", out)
	}
}

func TestRun_ConvertJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-json", "convert", "3232235786"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	var res cidr.ConversionResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if res.IPv4 != "192.168.1.10" {
		t.Errorf("got IPv4 %s, want 192.168.1.10", res.IPv4)
	}
	if res.Hex != "0xC0A8010A" {
		t.Errorf("got Hex %s, want 0xC0A8010A", res.Hex)
	}
}

func TestRun_ConvertMissingInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"convert"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for missing convert input, got %d", code)
	}
}

func TestRun_Aggregate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"aggregate", "10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	if out != "10.0.0.0/23" {
		t.Errorf("got %q, want %q", out, "10.0.0.0/23")
	}
}

func TestRun_Aggregate_Terraform(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-format=terraform", "aggregate", "192.168.0.0/24", "192.168.1.0/24"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	if out != `["192.168.0.0/23"]` {
		t.Errorf("got %q, want %q", out, `["192.168.0.0/23"]`)
	}
}

func TestRun_Overlap_Detected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Overlapping ranges should exit with code 1
	code := cli.Run([]string{"overlap", "10.100.0.0/16", "10.100.32.0/20"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for collision, got %d. stdout: %s", code, stdout.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "OVERLAP DETECTED") {
		t.Errorf("expected OVERLAP DETECTED, got:\n%s", out)
	}
}

func TestRun_Overlap_Clean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Non-overlapping ranges should exit with code 0
	code := cli.Run([]string{"overlap", "10.0.0.0/24", "10.0.1.0/24"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean check, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "NO OVERLAP") {
		t.Errorf("expected NO OVERLAP, got:\n%s", out)
	}
}

func TestRun_Overlap_JSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"-json", "overlap", "10.0.0.0/24", "10.0.0.128/25"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for collision in JSON mode, got %d", code)
	}

	var res cidr.OverlapResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if !res.Overlaps {
		t.Errorf("expected overlaps: true, got false")
	}
}

func TestRun_Contains_True(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"contains", "10.0.0.0/16", "10.0.5.1"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "YES: 10.0.0.0/16 contains 10.0.5.1") {
		t.Errorf("expected YES output, got:\n%s", out)
	}
}

func TestRun_Contains_False(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"contains", "10.0.0.0/16", "192.168.1.1"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for not-contains, got %d", code)
	}

	out := stdout.String()
	if !strings.Contains(out, "NO: 10.0.0.0/16 does not contain 192.168.1.1") {
		t.Errorf("expected NO output, got:\n%s", out)
	}
}

func TestRun_Exclude(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"exclude", "192.168.1.0/24", "192.168.1.128-192.168.1.255"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	if out != "192.168.1.0/25" {
		t.Errorf("got %q, want %q", out, "192.168.1.0/25")
	}
}

func TestRun_Split_ByPrefix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"split", "10.0.0.0/22", "/24"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 subnets, got %d: %v", len(lines), lines)
	}
	expected := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}
	for i, want := range expected {
		if lines[i] != want {
			t.Errorf("line[%d]: got %s, want %s", i, lines[i], want)
		}
	}
}

func TestRun_Split_ByCount(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"split", "10.0.0.0/22", "4"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 subnets, got %d", len(lines))
	}
}

func TestRun_Completion(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"completion", sh}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("completion %s failed with code %d: %s", sh, code, stderr.String())
		}
		if stdout.Len() == 0 {
			t.Errorf("completion %s generated empty output", sh)
		}
	}
}

func TestRun_FormatPresets(t *testing.T) {
	// Terraform
	{
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"-format=terraform", "192.168.1.10+1"}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("terraform format failed: %s", stderr.String())
		}
		if strings.TrimSpace(stdout.String()) != `["192.168.1.10/31"]` {
			t.Errorf("terraform format: got %s, want [\"192.168.1.10/31\"]", stdout.String())
		}
	}

	// CSV
	{
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"-format=csv", "192.168.1.0/24"}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("csv format failed: %s", stderr.String())
		}
		if !strings.Contains(stdout.String(), "cidr,start_ip,end_ip,count") {
			t.Errorf("expected CSV header, got:\n%s", stdout.String())
		}
	}

	// AWS
	{
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"-format=aws", "192.168.1.0/24"}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("aws format failed: %s", stderr.String())
		}
		if !strings.Contains(stdout.String(), `"CidrIp": "192.168.1.0/24"`) {
			t.Errorf("expected AWS CidrIp rule, got:\n%s", stdout.String())
		}
	}
}
