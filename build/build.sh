#!/usr/bin/env bash
#
# The entry point of a build of the work tree (enclave.md 11.1).
#
#   build/build.sh [--no-cache] [--release NAME] [eif|host|all]
#
#   eif    out/enclave.eif and out/measurements.json
#   host   the host image credential-enclave-host:{release}, from the files of out/
#   all    eif, then host (the default)
#
# The script prints the measurements (the content of out/measurements.json) to the standard
# output, or the name of the host image for `host`. Everything else goes to the standard error.
#
# `eif` runs the procedure builder/enclave-build.sh of this work tree on the commit HEAD of
# this work tree. The release name is `--release`, or the environment variable
# CREDENTIAL_ENCLAVE_RELEASE, or `dev`. The name is compiled into the node program, so two
# names give two sets of measurements.
#
# A release is not built with this script. The workflow enclave-build.yml builds the commit of
# a tag with the procedure of the commit of that workflow file, and attests the measurements.
# This script gives the same measurements when the files under builder/ of this work tree are
# those of that commit and the release name is the tag.
#
# Needs git, jq and Docker with buildx. The reference machine is Linux x86_64. On another
# machine Docker runs the same linux/amd64 programs under emulation: slower, and with the same
# output when the emulator runs every step. The tool that assembles the enclave image file has
# been observed to fail under the QEMU emulation of Docker Desktop.

set -euo pipefail

PLATFORM="linux/amd64"

say() {
    printf 'build: %s\n' "$*" >&2
}

fail() {
    printf 'build: %s\n' "$*" >&2
    exit 1
}

usage() {
    sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'
}

NO_CACHE=()
MODE="all"
RELEASE="${CREDENTIAL_ENCLAVE_RELEASE:-dev}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-cache)
            NO_CACHE=(--no-cache)
            shift
            ;;
        --release)
            RELEASE="${2:-}"
            shift 2
            ;;
        eif | host | all)
            MODE="$1"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

command -v git >/dev/null 2>&1 || fail "git is not installed"
command -v jq >/dev/null 2>&1 || fail "jq is not installed"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not available"

cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT="$ROOT/out"

build_eif() {
    "$ROOT/builder/enclave-build.sh" --source "$ROOT" --release "$RELEASE" --out "$OUT" \
        ${NO_CACHE[@]+"${NO_CACHE[@]}"} >/dev/null
}

build_host() {
    [ -f "$OUT/enclave.eif" ] && [ -f "$OUT/measurements.json" ] ||
        fail "out/enclave.eif and out/measurements.json do not exist: run build/build.sh eif"
    local commit release
    commit=$(git rev-parse --verify HEAD)
    [ "$(jq -er .git_commit "$OUT/measurements.json")" = "$commit" ] ||
        fail "out/measurements.json is not of the commit $commit: run build/build.sh eif"
    release=$(jq -er .release "$OUT/measurements.json")
    HOST_IMAGE="credential-enclave-host:$release"

    # The host program, nitro-cli and the files of out/. The public build proof of the release
    # (out/release-proofs.json) is in the image when the release workflow put it into out/.
    say "building the host image $HOST_IMAGE"
    git archive --format=tar HEAD | docker buildx build \
        --platform "$PLATFORM" \
        --provenance=false \
        --sbom=false \
        ${NO_CACHE[@]+"${NO_CACHE[@]}"} \
        --build-context "artifacts=$OUT" \
        --file build/Dockerfile.host \
        --output "type=docker,name=$HOST_IMAGE" \
        - >&2
    say "loaded the host image $HOST_IMAGE into the Docker daemon"
}

case "$MODE" in
    eif)
        build_eif
        cat "$OUT/measurements.json"
        ;;
    host)
        build_host
        printf '%s\n' "$HOST_IMAGE"
        ;;
    all)
        build_eif
        build_host
        cat "$OUT/measurements.json"
        ;;
esac
