#!/bin/bash

set -euo pipefail

# Rewrite all .pcap files under the repo's pcaps folder to .pcap.local for a given interface.
# Detects interface IP/MAC, then uses tcprewrite to make packets replayable on that interface.
# Skips files that are already up-to-date.

usage() {
  cat <<EOF

  $0 <interface>

Rewrites all *.pcap files in the assets/pcaps/ directory to be replayable on the given interface.
- Detects interface IP and MAC addresses automatically
- Sets both src/dst Ethernet MACs to the interface MAC
- Rewrites destination IPs to the interface IPv4
- Normalizes link type to Ethernet (except for loopback)
- Skips rewriting if the .pcap.local file is newer than the .pcap source

Each rewritten file is saved alongside the original as <name>.pcap.local

Requirements:
- tcprewrite (from tcpreplay suite)
- Interface must be up and have an IP address
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

iface="$1"

# Ensure tcprewrite exists
if ! command -v tcprewrite >/dev/null 2>&1; then
  echo "Error: 'tcprewrite' not found. Install tcpreplay suite and re-run." >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
pcaps_dir="$repo_root/assets/pcaps"

if [[ ! -d "$pcaps_dir" ]]; then
  echo "Info: directory '$pcaps_dir' does not exist; nothing to rewrite." >&2
  exit 0
fi

# Detect interface IP and MAC (macOS first, Linux fallback)
get_iface_ip() {
  local ifc="$1"
  if command -v ipconfig >/dev/null 2>&1; then
    ipconfig getifaddr "$ifc" 2>/dev/null || true
  elif command -v ip >/dev/null 2>&1; then
    ip -4 addr show "$ifc" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true
  fi
}

get_iface_mac() {
  local ifc="$1"
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig "$ifc" 2>/dev/null | awk '/ether/{print $2; exit}' || true
  elif command -v ip >/dev/null 2>&1; then
    ip link show "$ifc" 2>/dev/null | awk '/link\//{print $2; exit}' || true
  fi
}

MYIP=$(get_iface_ip "$iface")
MYMAC=$(get_iface_mac "$iface")

if [[ -z "${MYIP:-}" || -z "${MYMAC:-}" ]]; then
  echo "Error: can't detect ip/mac for $iface, make sure it is up" >&2
  exit 1
fi

shopt -s nullglob
pcap_files=("$pcaps_dir"/*.pcap)
shopt -u nullglob

if (( ${#pcap_files[@]} == 0 )); then
  echo "Info: no .pcap files found under '$pcaps_dir'; nothing to do." >&2
  exit 0
fi

echo "Using interface: $iface (IP: $MYIP, MAC: $MYMAC)"
rewritten=()
skipped=()
failed=()

for in_pcap in "${pcap_files[@]}"; do
  if [[ ! -f "$in_pcap" ]]; then
    continue
  fi
  
  in_base=$(basename "$in_pcap")
  out_base="${in_base%.pcap}.pcap.local"
  out_pcap="$(dirname "$in_pcap")/$out_base"

  # Skip if up-to-date
  if [[ -f "$out_pcap" && "$out_pcap" -nt "$in_pcap" ]]; then
    echo "Skip: $in_base (up-to-date)"
    skipped+=("$out_pcap")
    continue
  fi

  echo "Rewriting $(basename "$in_pcap") -> $(basename "$out_pcap")"
  
  args=(--fixcsum --infile "$in_pcap" --outfile "$out_pcap" \
        --enet-dmac "$MYMAC" --enet-smac "$MYMAC" \
        --dstipmap "0.0.0.0/0:${MYIP}/32")

  # Normalize DLT to Ethernet when not sending on loopback
  if [[ "$iface" != "lo" && "$iface" != "lo0" ]]; then
    args=(--dlt enet "${args[@]}")
  fi

  if ! tcprewrite "${args[@]}"; then
    echo "Error: tcprewrite failed for '$in_pcap'" >&2
    failed+=("$in_pcap")
    continue
  fi

  # sanity check
  if [[ ! -s "$out_pcap" ]]; then
    echo "Error: output '$out_pcap' not created or empty" >&2
    failed+=("$in_pcap")
    continue
  fi

  rewritten+=("$out_pcap")
  echo "Ok: $(basename "$out_pcap")"
done

echo
echo "Summary:"
echo "  Rewritten: ${#rewritten[@]}"
echo "  Skipped:   ${#skipped[@]}"
echo "  Failed:    ${#failed[@]}"

if (( ${#rewritten[@]} > 0 )); then
  for f in "${rewritten[@]}"; do echo "    $(basename "$f")"; done
fi
if (( ${#skipped[@]} > 0 )); then
  for f in "${skipped[@]}"; do echo "    $(basename "$f")"; done
fi
if (( ${#failed[@]} > 0 )); then
  echo "Some rewrites failed. See errors above." >&2
  exit 1
fi

echo "All pcaps are up-to-date."
echo
echo "Example usage:"
echo "sudo tcpdump -i $iface -n -vv -e udp dst port 36969"
echo "sudo tcpreplay -i $iface --pps 100 $pcaps_dir/<name>.pcap.local"
