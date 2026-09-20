#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
TAG_NAME="${2:-v${VERSION}}"
DIST_DIR="${3:-dist}"
OUT_FILE="${4:-${DIST_DIR}/cidr-calculator.rb}"

get_sha() {
  local file="$1"
  if [ -f "$file" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$file" | cut -d' ' -f1
    else
      echo "ERROR_NO_SHA_TOOL"
    fi
  else
    echo "REPLACE_WITH_SHA256"
  fi
}

SHA_DARWIN_ARM64=$(get_sha "${DIST_DIR}/cidr-calculator-${TAG_NAME}-darwin-arm64.tar.gz")
SHA_DARWIN_AMD64=$(get_sha "${DIST_DIR}/cidr-calculator-${TAG_NAME}-darwin-amd64.tar.gz")
SHA_LINUX_ARM64=$(get_sha "${DIST_DIR}/cidr-calculator-${TAG_NAME}-linux-arm64.tar.gz")
SHA_LINUX_AMD64=$(get_sha "${DIST_DIR}/cidr-calculator-${TAG_NAME}-linux-amd64.tar.gz")

mkdir -p "$(dirname "$OUT_FILE")"

cat <<EOF > "$OUT_FILE"
# typed: false
# frozen_string_literal: true

# This formula was auto-generated for cidr-calculator (https://github.com/smford/cidr-calculator).
class CidrCalculator < Formula
  desc "Convert IP ranges into minimal CIDR blocks with subnet intelligence"
  homepage "https://github.com/smford/cidr-calculator"
  version "${VERSION}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/smford/cidr-calculator/releases/download/v#{version}/cidr-calculator-v#{version}-darwin-arm64.tar.gz"
      sha256 "${SHA_DARWIN_ARM64}"
    end
    on_intel do
      url "https://github.com/smford/cidr-calculator/releases/download/v#{version}/cidr-calculator-v#{version}-darwin-amd64.tar.gz"
      sha256 "${SHA_DARWIN_AMD64}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/smford/cidr-calculator/releases/download/v#{version}/cidr-calculator-v#{version}-linux-arm64.tar.gz"
      sha256 "${SHA_LINUX_ARM64}"
    end
    on_intel do
      url "https://github.com/smford/cidr-calculator/releases/download/v#{version}/cidr-calculator-v#{version}-linux-amd64.tar.gz"
      sha256 "${SHA_LINUX_AMD64}"
    end
  end

  def install
    bin.install "cidr-calculator"
    generate_completions_from_executable(bin/"cidr-calculator", "completion")
  end

  test do
    assert_match "192.168.1.10/31", shell_output("#{bin}/cidr-calculator 192.168.1.10+1")
  end
end
EOF

echo "Generated Homebrew formula at ${OUT_FILE}"
