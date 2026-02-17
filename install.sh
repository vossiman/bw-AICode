#!/bin/bash
# install.sh — Symlink bwrap sandbox wrappers into ~/.local/bin
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
BIN_DIR="$HOME/.local/bin"

mkdir -p "$BIN_DIR"

for script in claude-bw.sh opencode-bw.sh; do
  name="${script%.sh}"
  target="$SCRIPT_DIR/$script"
  link="$BIN_DIR/$name"

  if [[ -L "$link" ]]; then
    echo "Updating: $link -> $target"
    ln -sf "$target" "$link"
  elif [[ -e "$link" ]]; then
    echo "Skipping: $link already exists and is not a symlink"
  else
    echo "Creating: $link -> $target"
    ln -s "$target" "$link"
  fi
done

echo "Done. Make sure $BIN_DIR is in your PATH."
