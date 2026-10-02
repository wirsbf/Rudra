#!/usr/bin/env bash
# build_ghidra_1204_headless.sh — build a runnable Ghidra 12.0.4 headless analyzer
# from the locked oracle source commit (ORACLE-0002 path 1).
#
# Locked oracle: tag Ghidra_12.0.4_build, commit e40ed13014025f82488b1f8f7bca566894ac376b.
#
# The local ghidra/ checkout is a sparse working tree, but the git object store
# contains the complete source at the locked commit (19739 files, incl. 15138
# .java files and every processor module). This script extracts that tree with
# `git archive` and builds it without mutating the checkout.
#
# Requirements (from Ghidra/application.properties at the locked commit):
#   application.java.min=21   -> a portable JDK 21 tarball in the work dir is fine
#   application.gradle.min=8.5 -> a portable Gradle distribution zip is fine
# Native toolchain (must already exist): make, g++, bison, flex, unzip.
# No root/system installation is required; every artifact lives in the work dir.
#
# Environment overrides:
#   RUDRA_HEADLESS_WORKDIR  build directory (default /tmp/rugra-ghidra-1204-headless)
#   RUDRA_JDK21_HOME        reuse an existing JDK >= 21 instead of downloading one
#   RUDRA_GRADLE_BIN        reuse an existing Gradle >= 8.5 instead of downloading one
#   RUDRA_GRADLE_VERSION    portable Gradle version to fetch (default 8.14.3)
#   RUDRA_GRADLE_WORKERS    max gradle workers (default 32)
#
# Output: a ready-to-run distribution under $WORKDIR/dist plus machine-readable
# RESULT_* lines on stdout. Exit 0 on success, 1 on any failure.

set -euo pipefail

# A libproxychains LD_PRELOAD hook intercepts every TCP connect() — including
# the Gradle client <-> daemon loopback IPC — and reroutes it to the socks
# proxy, which kills the daemon handshake ("first result from the daemon was
# empty"). Drop it for the whole build; Gradle gets proxy settings explicitly
# below.
unset LD_PRELOAD

LOCKED_ORACLE=e40ed13014025f82488b1f8f7bca566894ac376b
ORACLE_TAG=Ghidra_12.0.4_build
WORKDIR=${RUDRA_HEADLESS_WORKDIR:-/tmp/rugra-ghidra-1204-headless}
GRADLE_VERSION=${RUDRA_GRADLE_VERSION:-8.14.3}
GRADLE_WORKERS=${RUDRA_GRADLE_WORKERS:-32}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ghidra_repo=${RUDRA_GHIDRA_DIR:-"$repo_root/ghidra"}

log() { printf '[build_ghidra_1204_headless] %s\n' "$*"; }
die() { printf '[build_ghidra_1204_headless] BLOCKED: %s\n' "$*" >&2; exit 1; }

[[ -d "$ghidra_repo/.git" ]] || die "missing Ghidra repository: $ghidra_repo"
actual_head=$(git -C "$ghidra_repo" rev-parse HEAD)
[[ "$actual_head" = "$LOCKED_ORACLE" ]] || \
  die "Ghidra HEAD=$actual_head; expected $LOCKED_ORACLE"

for tool in make g++ bison flex unzip curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
done

mkdir -p "$WORKDIR"
cd "$WORKDIR"

# ---------------------------------------------------------------- source tree
src_dir="$WORKDIR/src"
source_archive="$WORKDIR/locked-source.tar"
if [[ ! -f "$src_dir/Ghidra/application.properties" ]]; then
  log "extracting full source tree of $LOCKED_ORACLE via git archive"
  git -C "$ghidra_repo" archive --format=tar --output="$source_archive" "$LOCKED_ORACLE"
  rm -rf "$src_dir"
  mkdir -p "$src_dir"
  tar -xf "$source_archive" -C "$src_dir"
fi
java_min=$(sed -n 's/^application\.java\.min=//p' "$src_dir/Ghidra/application.properties" | tr -d '[:space:]')
gradle_min=$(sed -n 's/^application\.gradle\.min=//p' "$src_dir/Ghidra/application.properties" | tr -d '[:space:]')
[[ -n "$java_min" ]] || die "cannot read application.java.min from extracted source"
log "source requires java>=$java_min gradle>=$gradle_min"

# Gradle does not read http_proxy/https_proxy env vars; if the environment
# only reaches the internet through a proxy, expose it to Gradle via
# systemProp lines appended to the extracted tree's gradle.properties
# (the extracted copy only — never the repository checkout).
if [[ -n "${https_proxy:-}${HTTPS_PROXY:-}" ]]; then
  proxy_url=${https_proxy:-${HTTPS_PROXY:-}}
  proxy_url=${proxy_url#http://}; proxy_url=${proxy_url#https://}
  proxy_host=${proxy_url%%:*}
  proxy_port=${proxy_url##*:}
  proxy_port=${proxy_port%%/*}
  if [[ -n "$proxy_host" && -n "$proxy_port" ]]; then
    if ! grep -q "regen.proxy.marker" "$src_dir/gradle.properties"; then
      cat >> "$src_dir/gradle.properties" <<EOF
# regen.proxy.marker (added by tools/build_ghidra_1204_headless.sh)
systemProp.http.proxyHost=$proxy_host
systemProp.http.proxyPort=$proxy_port
systemProp.https.proxyHost=$proxy_host
systemProp.https.proxyPort=$proxy_port
systemProp.http.nonProxyHosts=localhost|127.0.0.1
org.gradle.jvmargs=-Xmx4G -Duser.language=en -Duser.country=US -Dhttp.proxyHost=$proxy_host -Dhttp.proxyPort=$proxy_port -Dhttps.proxyHost=$proxy_host -Dhttps.proxyPort=$proxy_port -Dhttp.nonProxyHosts=localhost|127.0.0.1
EOF
    fi
    log "configured Gradle proxy $proxy_host:$proxy_port"
  fi
fi

# Ghidra's build.gradle refuses to configure unless a flatDir dependency
# directory exists; fetchDependencies.gradle (init script) populates it.
mkdir -p "$src_dir/dependencies/flatRepo"

# ---------------------------------------------------------------- JDK >= 21
jdk_home=""
if [[ -n "${RUDRA_JDK21_HOME:-}" ]]; then
  jdk_home="$RUDRA_JDK21_HOME"
elif [[ -x "$WORKDIR/jdk21/bin/java" ]]; then
  jdk_home="$WORKDIR/jdk21"
else
  jdk_tarball="$WORKDIR/jdk21.tar.gz"
  if [[ ! -f "$jdk_tarball" ]]; then
    log "downloading Temurin JDK $java_min (linux x64) from Adoptium"
    curl -fL --retry 3 -o "$jdk_tarball" \
      "https://api.adoptium.net/v3/binary/latest/${java_min}/ga/linux/x64/jdk/hotspot/normal/eclipse"
  fi
  rm -rf "$WORKDIR/jdk21" "$WORKDIR/jdk21-extract"
  mkdir -p "$WORKDIR/jdk21-extract"
  tar -xzf "$jdk_tarball" -C "$WORKDIR/jdk21-extract"
  extracted_dir=$(find "$WORKDIR/jdk21-extract" -maxdepth 1 -mindepth 1 -type d | head -1)
  mv "$extracted_dir" "$WORKDIR/jdk21"
  rmdir "$WORKDIR/jdk21-extract"
  jdk_home="$WORKDIR/jdk21"
fi
"$jdk_home/bin/java" -version 2>&1 | head -1 || die "JDK at $jdk_home does not run"
jdk_sha=$(sha256sum "$jdk_home/release" 2>/dev/null | cut -d' ' -f1 || true)

# ---------------------------------------------------------------- Gradle
gradle_bin=""
if [[ -n "${RUDRA_GRADLE_BIN:-}" ]]; then
  gradle_bin="$RUDRA_GRADLE_BIN"
elif [[ -x "$WORKDIR/gradle/bin/gradle" ]]; then
  gradle_bin="$WORKDIR/gradle/bin/gradle"
else
  gradle_zip="$WORKDIR/gradle-${GRADLE_VERSION}-bin.zip"
  if [[ ! -f "$gradle_zip" ]]; then
    log "downloading Gradle $GRADLE_VERSION"
    curl -fL --retry 3 -o "$gradle_zip" \
      "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
    curl -fL --retry 3 -o "$gradle_zip.sha256" \
      "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip.sha256"
  fi
  # gradle publishes a bare digest (no filename suffix), so parse it manually
  expected_gradle_sha=$(tr -d '[:space:]' < "gradle-${GRADLE_VERSION}-bin.zip.sha256")
  actual_gradle_sha=$(sha256sum "gradle-${GRADLE_VERSION}-bin.zip" | cut -d' ' -f1)
  [[ "$expected_gradle_sha" = "$actual_gradle_sha" ]] || \
    die "gradle distribution sha256 mismatch: $actual_gradle_sha != $expected_gradle_sha"
  unzip -q -o "$gradle_zip" -d "$WORKDIR"
  gradle_bin="$WORKDIR/gradle-${GRADLE_VERSION}/bin/gradle"
fi
log "using JDK: $jdk_home"
log "using Gradle: $gradle_bin"

# ---------------------------------------------------------------- build
export JAVA_HOME="$jdk_home"
export PATH="$jdk_home/bin:$PATH"
gradle_user_home="$WORKDIR/gradle-home"
cd "$src_dir"
if [[ ! -f "$src_dir/dependencies/flatRepo/.fetch-complete" ]]; then
  log "fetching Ghidra external dependencies (init script; downloads a lot)"
  "$gradle_bin" --no-daemon -g "$gradle_user_home" \
    -I gradle/support/fetchDependencies.gradle --info
  touch "$src_dir/dependencies/flatRepo/.fetch-complete"
fi
log "running gradle buildGhidra (workers=$GRADLE_WORKERS); this takes a long time"
GRADLE_OPTS="-Xmx8g -Dorg.gradle.daemon=false -Dorg.gradle.workers.max=$GRADLE_WORKERS" \
  "$gradle_bin" --no-daemon -g "$gradle_user_home" \
  -Dorg.gradle.workers.max="$GRADLE_WORKERS" \
  buildNatives allSleighCompile buildGhidra

# ---------------------------------------------------------------- dist
dist_zip=$(find "$src_dir/build/dist" -maxdepth 1 -name 'ghidra_*.zip' | head -1)
[[ -n "$dist_zip" ]] || die "buildGhidra completed but no distribution zip was produced"
rm -rf "$WORKDIR/dist"
mkdir -p "$WORKDIR/dist"
unzip -q "$dist_zip" -d "$WORKDIR/dist"
dist_root=$(find "$WORKDIR/dist" -maxdepth 1 -mindepth 1 -type d | head -1)
headless="$dist_root/support/analyzeHeadless"
[[ -x "$headless" ]] || die "analyzeHeadless missing in $dist_root"

# ---------------------------------------------------------------- smoke test
set +e
smoke_out=$("$headless" 2>&1)
smoke_rc=$?
set -e
if ! printf '%s\n' "$smoke_out" | grep -q "Headless Analyzer"; then
  die "analyzeHeadless smoke test failed (rc=$smoke_rc): $(printf '%s\n' "$smoke_out" | head -3)"
fi

cat > "$WORKDIR/build-environment.json" <<EOF
{
  "oracle_commit": "$LOCKED_ORACLE",
  "oracle_tag": "$ORACLE_TAG",
  "jdk_home": "$jdk_home",
  "jdk_release_sha256": "$jdk_sha",
  "gradle_version": "$GRADLE_VERSION",
  "distribution_zip": "$dist_zip",
  "distribution_root": "$dist_root",
  "analyzeHeadless": "$headless"
}
EOF

log "OK"
printf 'RESULT_DISTRIBUTION=%s\n' "$dist_root"
printf 'RESULT_ANALYZE_HEADLESS=%s\n' "$headless"
printf 'RESULT_ENVIRONMENT_JSON=%s\n' "$WORKDIR/build-environment.json"
