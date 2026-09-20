package cli

import (
	"fmt"
	"io"
	"strings"
)

// GenerateCompletion outputs the shell completion script for bash, zsh, or fish.
func GenerateCompletion(shell string, w io.Writer) error {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "bash":
		return generateBashCompletion(w)
	case "zsh":
		return generateZshCompletion(w)
	case "fish":
		return generateFishCompletion(w)
	default:
		return fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
}

func generateBashCompletion(w io.Writer) error {
	script := `#!/usr/bin/env bash
# Bash completion for cidr-calculator

_cidr_calculator() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="all nocidr info convert aggregate overlap contains exclude split completion -json -format= -s -summary -v -version -h -help"

    case "${prev}" in
        -format)
            COMPREPLY=( $(compgen -W "cidr json terraform tf csv aws" -- "${cur}") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
    return 0
}

complete -F _cidr_calculator cidr-calculator
`
	_, err := fmt.Fprint(w, script)
	return err
}

func generateZshCompletion(w io.Writer) error {
	script := `#compdef cidr-calculator
# Zsh completion for cidr-calculator

_cidr_calculator() {
    local -a commands
    local -a flags

    commands=(
        'all:Print all individual IP addresses'
        'nocidr:Suppress CIDR notation and only print IPs'
        'info:Display diagnostic, architectural, and subnet analysis'
        'convert:Convert IPv4 between integer, hex, binary, and dotted decimal'
        'aggregate:Merge adjacent/overlapping CIDRs into minimal supersets'
        'overlap:Check if two IP ranges or CIDRs intersect'
        'contains:Check if a parent range completely encloses a target range'
        'exclude:Subtract ranges from a base range'
        'split:Subdivide a parent CIDR into smaller subnets'
        'completion:Generate shell autocompletion script'
    )

    flags=(
        '-json[Output in structured JSON format]'
        '-format=[Specify output format]:format:(cidr json terraform tf csv aws)'
        '-s[Display summary metrics]'
        '-summary[Display summary metrics]'
        '-v[Show version information]'
        '-version[Show version information]'
        '-h[Show help]'
        '-help[Show help]'
    )

    _arguments \
        $flags \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe 'commands' commands
            ;;
    esac
}

_cidr_calculator "$@"
`
	_, err := fmt.Fprint(w, script)
	return err
}

func generateFishCompletion(w io.Writer) error {
	script := `# Fish completion for cidr-calculator

complete -c cidr-calculator -f

# Subcommands
complete -c cidr-calculator -n "__fish_use_subcommand" -a all -d "Print all individual IP addresses"
complete -c cidr-calculator -n "__fish_use_subcommand" -a nocidr -d "Suppress CIDR output"
complete -c cidr-calculator -n "__fish_use_subcommand" -a info -d "Display diagnostic and subnet analysis"
complete -c cidr-calculator -n "__fish_use_subcommand" -a convert -d "Convert IPv4 between integer, hex, binary, and dotted decimal"
complete -c cidr-calculator -n "__fish_use_subcommand" -a aggregate -d "Merge overlapping CIDRs into minimal supersets"
complete -c cidr-calculator -n "__fish_use_subcommand" -a overlap -d "Check if two ranges intersect"
complete -c cidr-calculator -n "__fish_use_subcommand" -a contains -d "Check if range contains target"
complete -c cidr-calculator -n "__fish_use_subcommand" -a exclude -d "Subtract ranges from a base range"
complete -c cidr-calculator -n "__fish_use_subcommand" -a split -d "Split a parent CIDR into subnets"
complete -c cidr-calculator -n "__fish_use_subcommand" -a completion -d "Generate shell completion script"

# Flags
complete -c cidr-calculator -l json -d "Output in JSON format"
complete -c cidr-calculator -l format -x -a "cidr json terraform tf csv aws" -d "Specify output format"
complete -c cidr-calculator -s s -l summary -d "Print summary metrics"
complete -c cidr-calculator -s v -l version -d "Show version"
complete -c cidr-calculator -s h -l help -d "Show help"
`
	_, err := fmt.Fprint(w, script)
	return err
}
