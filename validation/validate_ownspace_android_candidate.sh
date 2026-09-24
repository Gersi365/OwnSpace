#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

WORKSPACE=""
OUTPUT=""
EXPECTED_MAIN_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  validate_ownspace_android_candidate.sh \
    --workspace /absolute/path/to/ownspace-source \
    --output /new/output-directory \
    [--expected-main-sha256 SHA256]

Validates the Android client only. It never promotes source, installs an APK, or activates runtime state.
EOF
}

while (($#)); do
  case "$1" in
    --workspace) WORKSPACE="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --expected-main-sha256) EXPECTED_MAIN_SHA256="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

[[ -n "$WORKSPACE" && -n "$OUTPUT" ]] || { usage >&2; exit 64; }
[[ -d "$WORKSPACE" ]] || { printf 'ERROR: workspace not found\n' >&2; exit 66; }
[[ ! -e "$OUTPUT" ]] || { printf 'ERROR: output path already exists\n' >&2; exit 73; }

WORKSPACE="$(cd "$WORKSPACE" && pwd -P)"
ANDROID_DIR="$WORKSPACE/apps/android"
MAIN_ACTIVITY="$ANDROID_DIR/app/src/main/kotlin/com/privateworkspace/prw/MainActivity.kt"
[[ -f "$ANDROID_DIR/settings.gradle.kts" && -f "$ANDROID_DIR/app/build.gradle.kts" && -f "$MAIN_ACTIVITY" ]] || {
  printf 'ERROR: expected Ownspace Android source surface is incomplete\n' >&2
  exit 65
}

mkdir -m 0700 "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
REPORT="$OUTPUT/OWNSPACE_ANDROID_VALIDATION_REPORT.txt"
LOG="$OUTPUT/android-validation.log"

exec > >(tee "$LOG") 2>&1

sha() { sha256sum "$1" | awk '{print $1}'; }
record() { printf '%s=%s\n' "$1" "$2" >> "$REPORT"; }
fail() { record RESULT "FAIL:$1"; printf 'ERROR: %s\n' "$1" >&2; exit "${2:-1}"; }

: > "$REPORT"
record STATUS STARTED
record WORKSPACE "$WORKSPACE"
record MAIN_ACTIVITY_SHA256 "$(sha "$MAIN_ACTIVITY")"
record STARTED_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ -n "$EXPECTED_MAIN_SHA256" && "$(sha "$MAIN_ACTIVITY")" != "$EXPECTED_MAIN_SHA256" ]]; then
  fail "main_activity_hash_mismatch" 65
fi

for cmd in java gradle cargo rustc sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || fail "missing_$cmd" 69
done
command -v cargo-ndk >/dev/null 2>&1 || cargo ndk --version >/dev/null 2>&1 || fail "missing_cargo_ndk" 69

[[ -n "${ANDROID_HOME:-}" ]] || fail "missing_ANDROID_HOME" 69
[[ -d "$ANDROID_HOME/platforms/android-36" ]] || fail "missing_android_platform_36" 69
[[ -d "$ANDROID_HOME/ndk/28.2.13676358" ]] || fail "missing_ndk_28_2_13676358" 69

record JAVA_VERSION "$(java -version 2>&1 | head -n1)"
record GRADLE_VERSION "$(gradle --version | awk '/^Gradle /{print $2; exit}')"
record RUSTC_VERSION "$(rustc +1.97.1 --version 2>/dev/null || true)"
record CARGO_VERSION "$(cargo +1.97.1 --version 2>/dev/null || true)"
record CARGO_NDK_VERSION "$(cargo ndk --version 2>/dev/null | head -n1 || true)"
record ANDROID_HOME "$ANDROID_HOME"
record COMPILE_SDK 36
record TARGET_SDK 36
record MIN_SDK 29
record NDK_VERSION 28.2.13676358

rustc +1.97.1 --version | grep -q '^rustc 1\.97\.1 ' || fail "rust_1_97_1_unavailable" 69
cargo +1.97.1 --version | grep -q '^cargo 1\.97\.1 ' || fail "cargo_1_97_1_unavailable" 69

cd "$ANDROID_DIR"

run_stage() {
  local name="$1"; shift
  printf '\n===== %s =====\n' "$name"
  "$@"
  record "$name" PASS
}

run_stage UNIT_TEST gradle --no-daemon --stacktrace :app:testDebugUnitTest
run_stage LINT gradle --no-daemon --stacktrace :app:lintDebug
run_stage ASSEMBLE_DEBUG gradle --no-daemon --stacktrace :app:assembleDebug

APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
[[ -f "$APK" ]] || fail "debug_apk_missing_after_assemble" 1
record APK_PATH "$APK"
record APK_BYTES "$(stat -c %s "$APK")"
record APK_SHA256 "$(sha "$APK")"

record FINISHED_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record RESULT PASS
printf '\nRESULT=PASS\n'
