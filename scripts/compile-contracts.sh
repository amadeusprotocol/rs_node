#!/bin/bash

set -euo pipefail

# Compile all WAT contracts in the assets/contracts/ directory into WASM.
# Prefer `wat2wasm` (wabt). If unavailable, try `wasm-tools parse`.
# Skips files that are already up-to-date.

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
contracts_dir="$repo_root/assets/contracts"

usage() {
  cat <<EOF

  $0

Compiles all *.wat files in the assets/contracts/ directory into *.wasm next to them.
- Prefers 'wat2wasm' (from wabt). Falls back to 'wasm-tools parse' if available.
- Skips recompilation if the .wasm file is newer than the .wat source.

To install tools:
- wat2wasm: https://github.com/WebAssembly/wabt (e.g., brew install wabt)
- wasm-tools: https://github.com/bytecodealliance/wasm-tools (e.g., cargo install wasm-tools)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -d "$contracts_dir" ]]; then
  echo "Error: contracts directory not found at '$contracts_dir'" >&2
  exit 1
fi

# detect compiler
compile_mode=""
if command -v wat2wasm >/dev/null 2>&1; then
  compile_mode="wat2wasm"
elif command -v wasm-tools >/dev/null 2>&1; then
  compile_mode="wasm-tools"
else
  echo "Error: neither 'wat2wasm' nor 'wasm-tools' is installed." >&2
  echo "Install wabt (wat2wasm) or wasm-tools and re-run. See --help for tips." >&2
  exit 1
fi

shopt -s nullglob
wat_files=("$contracts_dir"/*.wat)
shopt -u nullglob

if (( ${#wat_files[@]} == 0 )); then
  echo "Info: no .wat files found under '$contracts_dir'; nothing to do." >&2
  exit 0
fi

echo "Using compiler: $compile_mode"
compiled=()
skipped=()
failed=()

for wat in "${wat_files[@]}"; do
  wasm="${wat%.wat}.wasm"

  # Skip if up-to-date
  if [[ -f "$wasm" && "$wasm" -nt "$wat" ]]; then
    echo "Skip: $(basename \"$wat\") (up-to-date)"
    skipped+=("$wasm")
    continue
  fi

  echo "Compiling $(basename "$wat") -> $(basename "$wasm")"
  if [[ "$compile_mode" == "wat2wasm" ]]; then
    if ! wat2wasm "$wat" -o "$wasm"; then
      echo "Error: wat2wasm failed for '$wat'" >&2
      failed+=("$wat")
      continue
    fi
  else
    # wasm-tools parse supports WAT input; try without flags first, then with --wat
    if ! wasm-tools parse "$wat" -o "$wasm" 2>/dev/null; then
      if ! wasm-tools parse --wat "$wat" -o "$wasm"; then
        echo "Error: wasm-tools parse failed for '$wat'" >&2
        failed+=("$wat")
        continue
      fi
    fi
  fi

  # sanity check
  if [[ ! -s "$wasm" ]]; then
    echo "Error: output '$wasm' not created or empty" >&2
    failed+=("$wat")
    continue
  fi

  compiled+=("$wasm")
  echo "Ok: $(basename "$wasm")"
done

echo
echo "Summary:"
echo "  Compiled: ${#compiled[@]}"
echo "  Skipped:  ${#skipped[@]}"
echo "  Failed:   ${#failed[@]}"

if (( ${#compiled[@]} > 0 )); then
  for f in "${compiled[@]}"; do echo "    $(basename "$f")"; done
fi
if (( ${#skipped[@]} > 0 )); then
  for f in "${skipped[@]}"; do echo "    $(basename "$f")"; done
fi
if (( ${#failed[@]} > 0 )); then
  echo "Some compilations failed. See errors above." >&2
  exit 1
fi

echo "All contracts are up-to-date."
