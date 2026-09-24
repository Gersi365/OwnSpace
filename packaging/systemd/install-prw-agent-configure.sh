#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: install-prw-agent-configure.sh --root ROOT --artifact ARTIFACT [--allow-root-filesystem]

Installs exactly one pre-built prw-agent-configure executable into:
  ROOT/usr/lib/private-remote-workspace/prw-agent-configure

The destination must be absent. The executable is never run by this installer.
ROOT=/ is refused unless --allow-root-filesystem is supplied explicitly.
EOF
  exit 64
}

root=
artifact=
allow_root_filesystem=0

while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || usage
      root=$2
      shift 2
      ;;
    --artifact)
      (($# >= 2)) || usage
      artifact=$2
      shift 2
      ;;
    --allow-root-filesystem)
      allow_root_filesystem=1
      shift
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$root" && -n "$artifact" ]] || usage
[[ "$root" = /* ]] || { echo "error: --root must be absolute" >&2; exit 65; }
[[ "$root" != *"/../"* && "$root" != */.. && "$root" != *"/./"* && "$root" != */. ]] || {
  echo "error: --root must be lexically normalized" >&2
  exit 65
}

if [[ "$root" == / && "$allow_root_filesystem" -ne 1 ]]; then
  echo "error: ROOT=/ requires explicit --allow-root-filesystem" >&2
  exit 66
fi

if [[ "$root" == / && "$(id -u)" -ne 0 ]]; then
  echo "error: ROOT=/ installation requires uid 0" >&2
  exit 66
fi

[[ -d "$root" && ! -L "$root" ]] || {
  echo "error: root must be an existing non-symlink directory" >&2
  exit 67
}

[[ -f "$artifact" && ! -L "$artifact" ]] || {
  echo "error: artifact must be a regular non-symlink file" >&2
  exit 68
}

artifact_name=$(basename -- "$artifact")
[[ "$artifact_name" == prw-agent-configure ]] || {
  echo "error: artifact basename must be prw-agent-configure" >&2
  exit 68
}

ensure_directory() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || {
      echo "error: unsafe directory component: $path" >&2
      exit 69
    }
    return
  fi
  mkdir -- "$path"
  chmod 0755 -- "$path"
}

ensure_directory "$root/usr"
ensure_directory "$root/usr/lib"
ensure_directory "$root/usr/lib/private-remote-workspace"

parent="$root/usr/lib/private-remote-workspace"
destination="$parent/prw-agent-configure"

if [[ -e "$destination" || -L "$destination" ]]; then
  echo "error: destination already exists; C03e-VE installer is create-only" >&2
  exit 70
fi

umask 077
tmp=$(mktemp "$parent/.prw-agent-configure.tmp.XXXXXX")
cleanup() {
  rm -f -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

cp -- "$artifact" "$tmp"
chmod 0755 -- "$tmp"

[[ -f "$tmp" && ! -L "$tmp" ]] || {
  echo "error: staged payload is not a regular non-symlink file" >&2
  exit 71
}
[[ "$(stat -c '%a' -- "$tmp")" == 755 ]] || {
  echo "error: staged payload mode mismatch" >&2
  exit 71
}
cmp -s -- "$artifact" "$tmp" || {
  echo "error: staged payload bytes mismatch" >&2
  exit 71
}

# Hard-link publication is an atomic no-replace operation on the same filesystem.
# If the destination appears after preflight, ln(1) fails with EEXIST rather than
# overwriting the competing object.
ln -- "$tmp" "$destination" || {
  echo "error: atomic no-replace publication failed" >&2
  exit 72
}
rm -f -- "$tmp"
trap - EXIT HUP INT TERM

[[ -f "$destination" && ! -L "$destination" ]] || {
  echo "error: installed payload is not a regular non-symlink file" >&2
  exit 73
}
[[ "$(stat -c '%a' -- "$destination")" == 755 ]] || {
  echo "error: installed payload mode mismatch" >&2
  exit 73
}
cmp -s -- "$artifact" "$destination" || {
  echo "error: installed payload bytes mismatch" >&2
  exit 73
}

if [[ "$root" == / ]]; then
  [[ "$(stat -c '%u:%g' -- "$destination")" == 0:0 ]] || {
    echo "error: real-root payload must be root-owned" >&2
    exit 73
  }
fi

printf 'installed=%s\n' "$destination"
