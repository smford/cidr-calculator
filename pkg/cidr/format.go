package cidr

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// OutputFormat defines the presentation format for CIDR and IP outputs.
type OutputFormat string

const (
	FormatCIDR      OutputFormat = "cidr"
	FormatJSON      OutputFormat = "json"
	FormatTerraform OutputFormat = "terraform"
	FormatTF        OutputFormat = "tf"
	FormatCSV       OutputFormat = "csv"
	FormatAWS       OutputFormat = "aws"
)

// AWSIngressRule models the JSON structure expected by AWS security group ingress tools.
type AWSIngressRule struct {
	CidrIP      string `json:"CidrIp,omitempty"`
	CidrIPV6    string `json:"CidrIpv6,omitempty"`
	Description string `json:"Description"`
}

// FormatPrefixes formats a list of prefixes into the requested IaC or data format.
func FormatPrefixes(prefixes []netip.Prefix, format OutputFormat) (string, error) {
	switch strings.ToLower(string(format)) {
	case string(FormatCIDR), "":
		var sb strings.Builder
		for _, p := range prefixes {
			sb.WriteString(p.String() + "\n")
		}
		return strings.TrimRight(sb.String(), "\n"), nil

	case string(FormatTerraform), string(FormatTF):
		list := make([]string, len(prefixes))
		for i, p := range prefixes {
			list[i] = fmt.Sprintf("%q", p.String())
		}
		return "[" + strings.Join(list, ", ") + "]", nil

	case string(FormatCSV):
		var sb strings.Builder
		sb.WriteString("cidr,start_ip,end_ip,count\n")
		for _, p := range prefixes {
			masked := p.Masked().Addr()
			pCount := PrefixIPCount(p)
			var endIP string
			if p.Addr().Is4() {
				startU, _ := IPv4ToUint32(masked)
				endIP = Uint32ToIPv4(startU + uint32(pCount-1)).String()
			} else {
				endIP = masked.String()
			}
			sb.WriteString(fmt.Sprintf("%s,%s,%s,%d\n", p, masked, endIP, pCount))
		}
		return strings.TrimRight(sb.String(), "\n"), nil

	case string(FormatAWS):
		rules := make([]AWSIngressRule, len(prefixes))
		for i, p := range prefixes {
			if p.Addr().Is6() {
				rules[i] = AWSIngressRule{
					CidrIPV6:    p.String(),
					Description: "Managed by cidr-calculator",
				}
			} else {
				rules[i] = AWSIngressRule{
					CidrIP:      p.String(),
					Description: "Managed by cidr-calculator",
				}
			}
		}
		b, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case string(FormatJSON):
		list := make([]string, len(prefixes))
		for i, p := range prefixes {
			list[i] = p.String()
		}
		b, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	default:
		return "", fmt.Errorf("unsupported output format %q (supported: cidr, json, terraform, csv, aws)", format)
	}
}
