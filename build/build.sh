#!/usr/bin/env bash
#
# The single entry point of the build (enclave.md 11.1).
#
#   build/build.sh [--no-cache] [eif|host|all]
#
#   eif    out/enclave.eif and out/measurements.json
#   host   the host image credential-enclave-host:{release}, from the files of out/
#   all    eif, then host (the default)
#
# The script prints the measurements (the content of out/measurements.json) to the standard
# output, or the name of the host image for `host`. Everything else goes to the standard error.
#
# Needs git and Docker with buildx, and nothing else. The reference machine is Linux x86_64.
# On another machine Docker runs the same linux/amd64 programs under emulation: slower, and
# with the same output when the emulator runs every step. The tool that assembles the enclave
# image file has been observed to fail under the QEMU emulation of Docker Desktop.
#
# What is built is the commit HEAD, not the work tree: the build context is `git archive HEAD`.
# The release tag is the `v*` tag of that commit, or `dev`.
#
# The identity of a release is PCR0, PCR1 and PCR2 of out/measurements.json. Two builds of one
# commit, on two machines, give the same three values. They do not give the same enclave image
# file: its metadata section holds the build time and is not measured.

set -euo pipefail

# BuildKit, fixed by digest. It builds the enclave image and stamps it with the commit time.
BUILDKIT_IMAGE="moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
# The one architecture of an enclave.
PLATFORM="linux/amd64"
# The socket of the Docker daemon, as the daemon sees it. nitro-cli reads the enclave image
# through it.
DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"

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

# The SHA-256 of the standard input, in hex.
sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d ' ' -f 1
    else
        shasum -a 256 | cut -d ' ' -f 1
    fi
}

# The SHA-256 of a file of the commit.
sha256_committed() {
    git show "HEAD:$1" | sha256_stdin
}

# The digest of the first image a committed Dockerfile is built `FROM`.
base_digest() {
    git show "HEAD:$1" | sed -n 's/^FROM [^ ]*@sha256:\([0-9a-f]\{64\}\).*/\1/p' | head -n 1
}

is_hex() {
    printf '%s' "$1" | grep -Eq "^[0-9a-f]{$2}\$"
}

NO_CACHE=""
MODE="all"
for argument in "$@"; do
    case "$argument" in
        --no-cache) NO_CACHE="--no-cache" ;;
        eif | host | all) MODE="$argument" ;;
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
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not available"

cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT="$ROOT/out"

# The build takes the files of the commit. A work tree that differs from the commit would give
# measurements of something the tree does not show, so the script stops.
git diff --quiet HEAD -- ||
    fail "the work tree has uncommitted changes: commit them first (the build takes the commit HEAD)"

GIT_COMMIT=$(git rev-parse --verify HEAD)
SHORT_COMMIT=$(printf '%s' "$GIT_COMMIT" | cut -c 1-12)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
RELEASE=$(git tag --list --points-at HEAD --sort=-version:refname 'v*' | head -n 1)
[ -n "$RELEASE" ] || RELEASE="dev"
case "$RELEASE" in
    *[!A-Za-z0-9._-]*) fail "the release tag $RELEASE holds a character outside A-Z a-z 0-9 . _ -" ;;
esac

NODE_IMAGE="credential-enclave-node:$SHORT_COMMIT"
TOOLS_IMAGE="credential-enclave-eif-tools:$SHORT_COMMIT"
HOST_IMAGE="credential-enclave-host:$RELEASE"
BUILDER="credential-enclave-$(printf '%s' "$BUILDKIT_IMAGE" | sed 's/.*@sha256:\(.\{12\}\).*/\1/')"

WORK=""
CONTAINER=""
cleanup() {
    [ -z "$CONTAINER" ] || docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# A BuildKit daemon of the fixed version, in a container of its own.
ensure_builder() {
    if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
        say "creating the BuildKit builder $BUILDER"
        docker buildx create --name "$BUILDER" --driver docker-container \
            --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
    fi
    docker buildx inspect --bootstrap "$BUILDER" >/dev/null
}

# Builds one image from the files of the commit and loads it into the Docker daemon.
#   build_image {Dockerfile} {exporter options} [more buildx arguments]
build_image() {
    local dockerfile="$1" output="$2"
    shift 2
    # NO_CACHE is empty or one word.
    # shellcheck disable=SC2086
    git archive --format=tar HEAD | docker buildx build \
        --builder "$BUILDER" \
        --platform "$PLATFORM" \
        --provenance=false \
        --sbom=false \
        $NO_CACHE \
        "$@" \
        --file "$dockerfile" \
        --output "$output" \
        - >&2
}

build_eif() {
    say "release $RELEASE, commit $GIT_COMMIT, commit time $SOURCE_DATE_EPOCH"
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/credential-enclave-build.XXXXXX")

    # Rows 1 and 2: the node program in an image built FROM scratch. BuildKit sets the creation
    # time of the image and the time of its one file to the commit time.
    say "building the enclave image $NODE_IMAGE"
    build_image build/Dockerfile.enclave \
        "type=docker,name=$NODE_IMAGE,rewrite-timestamp=true" \
        --build-arg "CREDENTIAL_ENCLAVE_RELEASE=$RELEASE" \
        --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

    CONTAINER=$(docker create --platform "$PLATFORM" "$NODE_IMAGE")
    docker cp "$CONTAINER:/credential-enclave" "$WORK/credential-enclave" >&2
    docker rm "$CONTAINER" >/dev/null
    CONTAINER=""
    local binary
    binary=$(sha256_stdin <"$WORK/credential-enclave")
    say "node program: sha256 $binary"

    # Row 3: nitro-cli turns the enclave image into the enclave image file.
    say "building the assembly tools $TOOLS_IMAGE"
    build_image build/Dockerfile.eif "type=docker,name=$TOOLS_IMAGE"

    say "assembling the enclave image file"
    CONTAINER=$(docker create --platform "$PLATFORM" \
        --volume "$DOCKER_SOCKET:/var/run/docker.sock" \
        --env "NODE_IMAGE=$NODE_IMAGE" \
        "$TOOLS_IMAGE" sh -euc '
            mkdir /work
            cd /work
            nitro-cli build-enclave --docker-uri "$NODE_IMAGE" --output-file enclave.eif >&2
            nitro-cli describe-eif --eif-path enclave.eif >describe-eif.json
            jq -e ".IsSigned == false" describe-eif.json >/dev/null
            for index in 0 1 2; do
                jq -er ".Measurements.PCR$index" describe-eif.json >"pcr$index"
            done
            cd /usr/share/nitro_enclaves/blobs
            sha256sum bzImage cmdline init linuxkit nsm.ko >/work/blobs.sha256
        ')
    docker start --attach "$CONTAINER" >&2
    docker cp "$CONTAINER:/work" "$WORK/assembly" >&2
    docker rm "$CONTAINER" >/dev/null
    CONTAINER=""

    local pcr0 pcr1 pcr2
    pcr0=$(cat "$WORK/assembly/pcr0")
    pcr1=$(cat "$WORK/assembly/pcr1")
    pcr2=$(cat "$WORK/assembly/pcr2")
    for value in "$pcr0" "$pcr1" "$pcr2"; do
        is_hex "$value" 96 || fail "nitro-cli gave a measurement that is not 96 hex digits"
    done

    # Row 4: the outputs. The table of inputs names what the three measurements were made of.
    local rust_image amazonlinux_image buildkit_image
    rust_image=$(base_digest build/Dockerfile.enclave)
    amazonlinux_image=$(base_digest build/Dockerfile.eif)
    buildkit_image=${BUILDKIT_IMAGE##*@sha256:}
    for value in "$rust_image" "$amazonlinux_image" "$buildkit_image" "$binary"; do
        is_hex "$value" 64 || fail "an input of the build has no SHA-256"
    done

    mkdir -p "$OUT"
    cp "$WORK/assembly/enclave.eif" "$OUT/enclave.eif"
    {
        printf '{\n'
        printf '  "release": "%s",\n' "$RELEASE"
        printf '  "git_commit": "%s",\n' "$GIT_COMMIT"
        printf '  "pcr0": "%s",\n' "$pcr0"
        printf '  "pcr1": "%s",\n' "$pcr1"
        printf '  "pcr2": "%s",\n' "$pcr2"
        printf '  "inputs": {\n'
        printf '    "image/rust": "%s",\n' "$rust_image"
        printf '    "image/buildkit": "%s",\n' "$buildkit_image"
        printf '    "image/amazonlinux": "%s",\n' "$amazonlinux_image"
        local file
        for file in rust-toolchain.toml Cargo.toml Cargo.lock \
            build/Dockerfile.enclave build/Dockerfile.eif build/build.sh; do
            printf '    "file/%s": "%s",\n' "$file" "$(sha256_committed "$file")"
        done
        local blob hash
        for blob in bzImage cmdline init linuxkit nsm.ko; do
            hash=$(awk -v name="$blob" '$2 == name { print $1 }' "$WORK/assembly/blobs.sha256")
            is_hex "$hash" 64 || fail "the blob $blob has no SHA-256"
            printf '    "blob/%s": "%s",\n' "$blob" "$hash"
        done
        printf '    "binary/credential-enclave": "%s"\n' "$binary"
        printf '  }\n'
        printf '}\n'
    } >"$OUT/measurements.json"

    say "wrote out/enclave.eif (sha256 $(sha256_stdin <"$OUT/enclave.eif"))"
    say "wrote out/measurements.json"
}

build_host() {
    [ -f "$OUT/enclave.eif" ] && [ -f "$OUT/measurements.json" ] ||
        fail "out/enclave.eif and out/measurements.json do not exist: run build/build.sh eif"
    grep -q "\"git_commit\": \"$GIT_COMMIT\"" "$OUT/measurements.json" ||
        fail "out/measurements.json is not of the commit $GIT_COMMIT: run build/build.sh eif"
    grep -q "\"release\": \"$RELEASE\"" "$OUT/measurements.json" ||
        fail "out/measurements.json is not of the release $RELEASE: run build/build.sh eif"

    # Row 5: the host program, nitro-cli and the two files of out/.
    say "building the host image $HOST_IMAGE"
    build_image build/Dockerfile.host "type=docker,name=$HOST_IMAGE" \
        --build-context "artifacts=$OUT"
    say "loaded the host image $HOST_IMAGE into the Docker daemon"
}

ensure_builder
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
