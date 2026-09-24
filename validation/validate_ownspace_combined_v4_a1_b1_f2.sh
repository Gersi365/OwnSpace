#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

BASE_ARCHIVE=""
BASE_MANIFEST=""
V4_PATCH=""
A1_PATCH=""
B1_PATCH=""
F1_PATCH=""
F2_PATCH=""
COMBINED_MANIFEST=""
ANDROID_RUNNER=""
OUTPUT=""
MODE="static"

EXPECTED_BASE_ARCHIVE_SHA256="6b981dde40d5675620b7030b8b76c28fadfd89121caf0e5845f487ceeaaf87c4"
EXPECTED_BASE_MANIFEST_SHA256="b2c137728846635c2f872fd3f2f8b059655505856b1988a5cac92f9268896742"
EXPECTED_V4_PATCH_SHA256="13608ead93378aad8fea2f76b9fd0b63bb8cee5dcf0512a54d4e60b6c8a1fb9f"
EXPECTED_A1_PATCH_SHA256="11eb59d62cfcb9da3057e3debcc10e4d48ff77a5279b30cfb2ee7244ef12c4f0"
EXPECTED_B1_PATCH_SHA256="40b4655c51cbf33618830c8c2cef73ca2051049e1dd2dba23d3e4b65874deb96"
EXPECTED_F1_PATCH_SHA256="27d6b520d6e2e290913f7f86bbb5f0339e9b6735e259f70eea5fcf36ee44243e"
EXPECTED_F2_PATCH_SHA256="fe9af5847028b9086aa6f24e8b170525f27053f2eff01c69e43677a5c01f6ee9"
EXPECTED_COMBINED_MANIFEST_SHA256="5d3478a967238ec463a8350f3d5d5d5c3d99906d615367d80dc3e678f8c8652f"
EXPECTED_ANDROID_RUNNER_SHA256="f35257e4816889dfaeec05d48ad65ff2c72d5d11eeb49259a04fcb18be197065"
EXPECTED_COMBINED_MAIN_ACTIVITY_SHA256="6af8b3ee3ffa40bf8614594b827b442d93f611c06f4735dce7ed19d217fe37f7"
EXPECTED_SOURCE_FILES=372

usage() {
  cat <<'EOF'
Usage:
  validate_ownspace_combined_v4_a1_b1_f1.sh \
    --base-archive /path/to/Ownspace_Source_Current_2026-09-24.tar.gz \
    --base-manifest /path/to/OWNSPACE_SOURCE_MANIFEST_SHA256.txt \
    --v4-patch /path/to/OWNSPACE_TEMP_STARTUP_AUTHORITY_V4.patch \
    --a1-patch /path/to/OWNSPACE_TEMP_ANDROID_UI_A1.patch \
    --b1-patch /path/to/OWNSPACE_TEMP_DESKTOP_UI_B1.patch \
    --f1-patch /path/to/OWNSPACE_TEMP_FORMAT_F1.patch \
    --f2-patch /path/to/OWNSPACE_TEMP_CLIPPY_F2.patch \
    --combined-manifest /path/to/OWNSPACE_TEMP_COMBINED_V4_A1_B1_F2_MANIFEST_SHA256.txt \
    --android-runner /path/to/validate_ownspace_android_candidate.sh \
    --output /new/output-directory \
    [--mode static|full]

static: exact input verification + baseline replay + V4/A1/B1/F1/F2 composition + combined manifest proof.
full: static mode plus full Rust workspace validation and Android unit/lint/assembleDebug validation.
EOF
}

while (($#)); do
  case "$1" in
    --base-archive) BASE_ARCHIVE="${2:-}"; shift 2 ;;
    --base-manifest) BASE_MANIFEST="${2:-}"; shift 2 ;;
    --v4-patch) V4_PATCH="${2:-}"; shift 2 ;;
    --a1-patch) A1_PATCH="${2:-}"; shift 2 ;;
    --b1-patch) B1_PATCH="${2:-}"; shift 2 ;;
    --f1-patch) F1_PATCH="${2:-}"; shift 2 ;;
    --f2-patch) F2_PATCH="${2:-}"; shift 2 ;;
    --combined-manifest) COMBINED_MANIFEST="${2:-}"; shift 2 ;;
    --android-runner) ANDROID_RUNNER="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

[[ "$MODE" == "static" || "$MODE" == "full" ]] || { printf 'ERROR: invalid mode\n' >&2; exit 64; }
for var in BASE_ARCHIVE BASE_MANIFEST V4_PATCH A1_PATCH B1_PATCH F1_PATCH F2_PATCH COMBINED_MANIFEST ANDROID_RUNNER OUTPUT; do
  [[ -n "${!var}" ]] || { printf 'ERROR: missing required argument: %s\n' "$var" >&2; exit 64; }
done
for f in "$BASE_ARCHIVE" "$BASE_MANIFEST" "$V4_PATCH" "$A1_PATCH" "$B1_PATCH" "$F1_PATCH" "$F2_PATCH" "$COMBINED_MANIFEST" "$ANDROID_RUNNER"; do
  [[ -f "$f" ]] || { printf 'ERROR: input file missing: %s\n' "$f" >&2; exit 66; }
done
[[ ! -e "$OUTPUT" ]] || { printf 'ERROR: output already exists\n' >&2; exit 73; }

for cmd in sha256sum tar patch find wc mktemp date realpath; do
  command -v "$cmd" >/dev/null 2>&1 || { printf 'ERROR: missing tool: %s\n' "$cmd" >&2; exit 69; }
done

BASE_ARCHIVE="$(realpath "$BASE_ARCHIVE")"
BASE_MANIFEST="$(realpath "$BASE_MANIFEST")"
V4_PATCH="$(realpath "$V4_PATCH")"
A1_PATCH="$(realpath "$A1_PATCH")"
B1_PATCH="$(realpath "$B1_PATCH")"
F1_PATCH="$(realpath "$F1_PATCH")"
F2_PATCH="$(realpath "$F2_PATCH")"
COMBINED_MANIFEST="$(realpath "$COMBINED_MANIFEST")"
ANDROID_RUNNER="$(realpath "$ANDROID_RUNNER")"

sha() { sha256sum "$1" | awk '{print $1}'; }
assert_sha() {
  local f="$1" expected="$2" label="$3"
  local actual; actual="$(sha "$f")"
  [[ "$actual" == "$expected" ]] || { printf 'ERROR: %s hash mismatch: %s\n' "$label" "$actual" >&2; exit 65; }
}

assert_sha "$BASE_ARCHIVE" "$EXPECTED_BASE_ARCHIVE_SHA256" base_archive
assert_sha "$BASE_MANIFEST" "$EXPECTED_BASE_MANIFEST_SHA256" base_manifest
assert_sha "$V4_PATCH" "$EXPECTED_V4_PATCH_SHA256" v4_patch
assert_sha "$A1_PATCH" "$EXPECTED_A1_PATCH_SHA256" a1_patch
assert_sha "$B1_PATCH" "$EXPECTED_B1_PATCH_SHA256" b1_patch
assert_sha "$F1_PATCH" "$EXPECTED_F1_PATCH_SHA256" f1_patch
assert_sha "$F2_PATCH" "$EXPECTED_F2_PATCH_SHA256" f2_patch
assert_sha "$COMBINED_MANIFEST" "$EXPECTED_COMBINED_MANIFEST_SHA256" combined_manifest
assert_sha "$ANDROID_RUNNER" "$EXPECTED_ANDROID_RUNNER_SHA256" android_runner

mkdir -m 0700 "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
REPORT="$OUTPUT/OWNSPACE_COMBINED_V4_A1_B1_VALIDATION_REPORT.txt"
LOG="$OUTPUT/combined-validation.log"
exec > >(tee "$LOG") 2>&1

record() { printf '%s=%s\n' "$1" "$2" >> "$REPORT"; }
fail() { record RESULT "FAIL:$1"; printf 'ERROR: %s\n' "$1" >&2; exit "${2:-1}"; }
: > "$REPORT"
record MODE "$MODE"
record STARTED_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record BASE_ARCHIVE_SHA256 "$EXPECTED_BASE_ARCHIVE_SHA256"
record V4_PATCH_SHA256 "$EXPECTED_V4_PATCH_SHA256"
record A1_PATCH_SHA256 "$EXPECTED_A1_PATCH_SHA256"
record B1_PATCH_SHA256 "$EXPECTED_B1_PATCH_SHA256"
record F1_PATCH_SHA256 "$EXPECTED_F1_PATCH_SHA256"
record F2_PATCH_SHA256 "$EXPECTED_F2_PATCH_SHA256"
record COMBINED_MANIFEST_SHA256 "$EXPECTED_COMBINED_MANIFEST_SHA256"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
WORK="$TMP/source"
mkdir "$WORK"
tar -xzf "$BASE_ARCHIVE" -C "$WORK"

cd "$WORK"
BASE_COUNT="$(find . -type f | wc -l | tr -d ' ')"
[[ "$BASE_COUNT" == "$EXPECTED_SOURCE_FILES" ]] || fail "baseline_file_count_$BASE_COUNT" 65
sha256sum -c "$BASE_MANIFEST" >/dev/null || fail "baseline_manifest_check" 65
record BASELINE_MANIFEST PASS

for spec in "V4:$V4_PATCH" "A1:$A1_PATCH" "B1:$B1_PATCH" "F1:$F1_PATCH" "F2:$F2_PATCH"; do
  name="${spec%%:*}"
  file="${spec#*:}"
  patch -p1 --dry-run < "$file" >/dev/null || fail "${name}_patch_dry_run" 65
  patch -p1 < "$file" >/dev/null || fail "${name}_patch_apply" 65
  record "${name}_PATCH" PASS
done

if find . -type f \( -name '*.rej' -o -name '*.orig' \) -print -quit | grep -q .; then
  fail "patch_artifact_present" 65
fi

COMBINED_COUNT="$(find . -type f | wc -l | tr -d ' ')"
MANIFEST_COUNT="$(wc -l < "$COMBINED_MANIFEST" | tr -d ' ')"
[[ "$COMBINED_COUNT" == "$EXPECTED_SOURCE_FILES" ]] || fail "combined_file_count_$COMBINED_COUNT" 65
[[ "$MANIFEST_COUNT" == "$EXPECTED_SOURCE_FILES" ]] || fail "combined_manifest_count_$MANIFEST_COUNT" 65
sha256sum -c "$COMBINED_MANIFEST" >/dev/null || fail "combined_manifest_check" 65
record COMBINED_MANIFEST PASS

MAIN_ACTIVITY="apps/android/app/src/main/kotlin/com/privateworkspace/prw/MainActivity.kt"
[[ "$(sha "$MAIN_ACTIVITY")" == "$EXPECTED_COMBINED_MAIN_ACTIVITY_SHA256" ]] || fail "combined_main_activity_hash" 65
record MAIN_ACTIVITY_SHA256 "$EXPECTED_COMBINED_MAIN_ACTIVITY_SHA256"
record STATIC_RESULT PASS

if [[ "$MODE" == "static" ]]; then
  record FINISHED_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  record RESULT PASS
  printf 'RESULT=PASS\n'
  exit 0
fi

for cmd in cargo rustc rustfmt; do
  command -v "$cmd" >/dev/null 2>&1 || fail "missing_$cmd" 69
done
rustc --version | grep -q '^rustc 1\.97\.1 ' || fail "rust_1_97_1_required" 69
cargo --version | grep -q '^cargo 1\.97\.1 ' || fail "cargo_1_97_1_required" 69
record RUSTC_VERSION "$(rustc --version)"
record CARGO_VERSION "$(cargo --version)"

run_stage() {
  local name="$1"; shift
  printf '\n===== %s =====\n' "$name"
  "$@"
  record "$name" PASS
}

run_stage CARGO_METADATA cargo metadata --locked --no-deps --format-version 1
run_stage CARGO_FMT cargo fmt --all -- --check
run_stage CARGO_CLIPPY cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run_stage CARGO_TEST cargo test --locked --workspace --all-targets
run_stage CARGO_BUILD cargo build --locked --workspace --all-targets

ANDROID_OUT="$OUTPUT/android"
"$ANDROID_RUNNER" \
  --workspace "$WORK" \
  --output "$ANDROID_OUT" \
  --expected-main-sha256 "$EXPECTED_COMBINED_MAIN_ACTIVITY_SHA256"
record ANDROID_VALIDATION PASS

record FINISHED_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record RESULT PASS
printf 'RESULT=PASS\n'
