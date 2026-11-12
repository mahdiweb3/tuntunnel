#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'Run this installer as root.' >&2
  exit 1
fi
# Set TUNTUNNEL_URL to the raw URL of tunnel-extra.sh in your GitHub repository.
url="${TUNTUNNEL_URL:-https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/tunnel-extra.sh}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$tmp"
bash -n "$tmp"
install -d -m 755 /usr/local/lib/tunnel-extra /usr/local/bin
install -m 755 "$tmp" /usr/local/lib/tunnel-extra/tunnel-extra.sh
ln -sfn /usr/local/lib/tunnel-extra/tunnel-extra.sh /usr/local/bin/tuntunnel
rm -f "$tmp"
trap - EXIT
printf '%s\n' 'Installed. Run tuntunnel to open the menu.'
if [ -t 0 ]; then
  exec /usr/local/bin/tuntunnel
fi
if { exec 3<>/dev/tty; } 2>/dev/null; then
  exec /usr/local/bin/tuntunnel <&3
fi
printf '%s\n' 'No interactive terminal detected; run tuntunnel in a terminal.'
