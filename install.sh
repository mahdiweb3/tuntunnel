#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Run this installer as root.' >&2; exit 1; }
url="${TUNTUNNEL_URL:-https://raw.githubusercontent.com/mahdiweb3/tuntunnel/main/tunnel-extra.sh}"
install -d -m 755 /usr/local/lib/tunnel-extra /usr/local/bin
file=/usr/local/lib/tunnel-extra/tunnel-extra.sh
trap 'rm -f "$file.new"' EXIT
curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$file.new"
bash -n "$file.new"
chmod 755 "$file.new"
mv -f "$file.new" "$file"
ln -sfn "$file" /usr/local/bin/tuntunnel
printf '%s\n' 'Installed. Run tuntunnel to open the menu.'
if [ -t 0 ]; then
    exec /usr/local/bin/tuntunnel
fi
if { exec 3<>/dev/tty; } 2>/dev/null; then
    exec /usr/local/bin/tuntunnel <&3
fi
printf '%s\n' 'No interactive terminal detected; run tuntunnel in a terminal.'
