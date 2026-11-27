#!/usr/bin/env bash
#
# The build of the enclave image file of one commit (enclave.md 11.1).
#
#   builder/enclave-build.sh --source DIR --release NAME --out DIR [--no-cache]
#
#   --source   a git work tree. What is built is its commit HEAD, not the files of the tree.
#   --release  the name of the release: the tag that started the build, or `dev`.
#   --out      receives enclave.eif and measurements.json.
#
# The script prints the content of measurements.json to the standard output. Everything else
# goes to the standard error.
#
# This file and the files beside it are the procedure of the build. They are not taken from
# the commit that is built: the workflow enclave-build.yml runs the copy of its own commit on
# the commit of a tag. A commit decides three things about its build and nothing else:
#
#   - its sources and Cargo.lock;
#   - how the node program is compiled: build/Dockerfile.enclave, whose last stage holds the
#     one file /credential-enclave;
#   - the images that Dockerfile is built from: build/inputs.json names each by digest.
#
# No program of the commit runs with a network. The steps are:
#
#   1. checks of the commit: every package of Cargo.lock is from crates.io, no path of the
#      commit is a cargo configuration directory, every image of build/inputs.json is named by
#      digest;
#   2. the packages of Cargo.lock, from crates.io, with `cargo vendor` of the image this file
#      fixes. cargo checks each package against its checksum in Cargo.lock, and vendoring
#      compiles nothing and runs no build script;
#   3. the images of build/inputs.json, from their registries, by digest, to directories;
#   4. the compilation, by a BuildKit daemon whose container has no network. The Dockerfile of
#      the commit, the build scripts and the procedural macros run here. The build context is
#      the files of the commit, the packages of step 2 and the images of step 3;
#   5. the enclave image file, assembled and measured by the nitro-cli of the image this
#      procedure fixes (Dockerfile.eif beside this file);
#   6. measurements.json, written by this script: the release, the commit, and the three
#      measurements step 5 read from the enclave image file. No file of the commit states a
#      value of it.
#
# Needs git, jq and Docker with buildx. The reference machine is Linux x86_64. Two builds of one
# commit under one release name give the same PCR0, PCR1 and PCR2 on two machines. They do not
# give the same enclave image file: its metadata section holds the build time and is not
# measured.

set -euo pipefail

# BuildKit, fixed by digest. One daemon of it has a network and fetches; another has none and
# compiles.
BUILDKIT_IMAGE="moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
# The image whose cargo vendors the packages of Cargo.lock. It runs no program of the commit.
CARGO_IMAGE="rust:1.98.1-alpine3.24@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f"
# The one architecture of an enclave.
PLATFORM="linux/amd64"
# The socket of the Docker daemon, as the daemon sees it. nitro-cli reads the enclave image
# through it.
DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"

say() {
    printf 'enclave-build: %s\n' "$*" >&2
}

fail() {
    printf 'enclave-build: %s\n' "$*" >&2
    exit 1
}

usage() {
    sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
}

# The SHA-256 of the standard input, in hex.
sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d ' ' -f 1
    else
        shasum -a 256 | cut -d ' ' -f 1
    fi
}

is_hex() {
    printf '%s' "$1" | grep -Eq "^[0-9a-f]{$2}\$"
}

# The modification time of a file, in seconds since 1970.
file_time() {
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"
}

SOURCE=""
RELEASE=""
OUT=""
NO_CACHE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source)
            SOURCE="${2:-}"
            shift 2
            ;;
        --release)
            RELEASE="${2:-}"
            shift 2
            ;;
        --out)
            OUT="${2:-}"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
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
[ -n "$SOURCE" ] && [ -n "$RELEASE" ] && [ -n "$OUT" ] || {
    usage >&2
    exit 2
}

command -v git >/dev/null 2>&1 || fail "git is not installed"
command -v jq >/dev/null 2>&1 || fail "jq is not installed"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not available"

PROCEDURE=$(cd "$(dirname "$0")" && pwd)
SOURCE=$(cd "$SOURCE" && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

case "$RELEASE" in
    "" | *[!A-Za-z0-9._-]*) fail "the release name $RELEASE holds a character outside A-Z a-z 0-9 . _ -" ;;
esac

# The build takes the files of the commit. A work tree that differs from the commit would give
# measurements of something the tree does not show, so the script stops.
git -C "$SOURCE" diff --quiet HEAD -- ||
    fail "the work tree has uncommitted changes: commit them first (the build takes the commit HEAD)"

GIT_COMMIT=$(git -C "$SOURCE" rev-parse --verify HEAD)
SHORT_COMMIT=$(printf '%s' "$GIT_COMMIT" | cut -c 1-12)
SOURCE_DATE_EPOCH=$(git -C "$SOURCE" log -1 --format=%ct HEAD)

# A file of the commit, to the standard output.
committed() {
    git -C "$SOURCE" cat-file blob "$GIT_COMMIT:$1"
}

NODE_IMAGE="credential-enclave-node:$SHORT_COMMIT"
TOOLS_IMAGE="credential-enclave-eif-tools:$(sha256_stdin <"$PROCEDURE/Dockerfile.eif" | cut -c 1-12)"
BUILDKIT_ID=$(printf '%s' "$BUILDKIT_IMAGE" | sed 's/.*@sha256:\(.\{12\}\).*/\1/')
FETCHER="credential-enclave-fetch-$BUILDKIT_ID"
SEALED="credential-enclave-sealed-$BUILDKIT_ID"

# The work directory is under the output directory: a Docker daemon in a virtual machine sees
# the directories the user shares with it, and the directory of temporary files is not always
# one of them.
WORK="$OUT/.enclave-build"
CONTAINER=""
cleanup() {
    [ -z "$CONTAINER" ] || docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
rm -rf "$WORK"
mkdir -p "$WORK"

# ---- 1. The checks of the commit.

say "release $RELEASE, commit $GIT_COMMIT, commit time $SOURCE_DATE_EPOCH"

for file in Cargo.toml Cargo.lock build/Dockerfile.enclave build/inputs.json; do
    mode=$(git -C "$SOURCE" ls-tree "$GIT_COMMIT" -- "$file" | cut -d ' ' -f 1)
    case "$mode" in
        100644 | 100755) ;;
        *) fail "$file is not a regular file of the commit" ;;
    esac
done

# Every package of Cargo.lock comes from crates.io: step 2 downloads what Cargo.lock names.
committed Cargo.lock | awk '
    /^source = / && $0 != "source = \"registry+https://github.com/rust-lang/crates.io-index\"" { other = 1; print > "/dev/stderr" }
    END { exit other }' ||
    fail "Cargo.lock of the commit names a package from another place than crates.io"

# No cargo configuration in the commit: a configuration file can send the download of step 2
# to another place or name a program for cargo to run.
if git -C "$SOURCE" ls-tree -r --name-only "$GIT_COMMIT" | grep -Eq '(^|/)\.cargo(/|$)'; then
    fail "the commit holds a .cargo path: the build takes no cargo configuration from a commit"
fi

# The images of the commit: each a name the Dockerfile builds FROM, and a reference by digest.
committed build/inputs.json >"$WORK/inputs.json"
jq -e '
    type == "object"
    and (.images | type == "object" and length >= 1 and length <= 8)
    and ([.images | to_entries[]
          | (.key | test("^[a-z][a-z0-9-]{0,31}$"))
            and (.value | type == "string"
                 and test("^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$"))]
         | all)' "$WORK/inputs.json" >/dev/null ||
    fail "build/inputs.json of the commit is not {\"images\": {name: \"registry/path@sha256:digest\"}}"

# ---- The two BuildKit daemons.

# One BuildKit daemon of the fixed version, in a container of its own.
#   ensure_builder {name} [driver options]
ensure_builder() {
    local name="$1"
    shift
    if ! docker buildx inspect "$name" >/dev/null 2>&1; then
        say "creating the BuildKit builder $name"
        docker buildx create --name "$name" --driver docker-container \
            --driver-opt "image=$BUILDKIT_IMAGE" "$@" >/dev/null
    fi
    docker buildx inspect --bootstrap "$name" >/dev/null
}

ensure_builder "$FETCHER"
# The container of this daemon has no network interface but loopback. Nothing a Dockerfile
# says (a RUN step, an ADD of an address, an image of a FROM or of a COPY --from, another
# frontend) reaches anything outside the build context.
ensure_builder "$SEALED" --driver-opt network=none

# ---- 2. The packages of Cargo.lock.

say "vendoring the packages of Cargo.lock"
mkdir -p "$WORK/commit" "$WORK/vendor" "$WORK/empty"
git -C "$SOURCE" archive --format=tar "$GIT_COMMIT" | tar -x -C "$WORK/commit"
docker buildx build \
    --builder "$FETCHER" \
    --platform "$PLATFORM" \
    --provenance=false \
    --sbom=false \
    --build-arg "CARGO_IMAGE=$CARGO_IMAGE" \
    --file "$PROCEDURE/Dockerfile.vendor" \
    --output "type=local,dest=$WORK/vendor" \
    "$WORK/commit" >&2
[ -f "$WORK/vendor/.vendored" ] || fail "the packages of Cargo.lock were not vendored"
rm -f "$WORK/vendor/.vendored"
rm -rf "$WORK/commit"

# ---- 3. The images of build/inputs.json.

CONTEXTS=()
INPUT_LINES=""
while IFS=$'\t' read -r name reference; do
    say "fetching the image $name ($reference)"
    mkdir -p "$WORK/images/$name"
    printf 'FROM %s\n' "$reference" | docker buildx build \
        --builder "$FETCHER" \
        --platform "$PLATFORM" \
        --provenance=false \
        --sbom=false \
        --file - \
        --output "type=oci,dest=$WORK/images/$name,tar=false" \
        "$WORK/empty" >&2
    layout_digest=$(jq -er '.manifests[0].digest' "$WORK/images/$name/index.json")
    CONTEXTS+=(--build-context "$name=oci-layout://$WORK/images/$name@$layout_digest")
    INPUT_LINES="$INPUT_LINES$(printf '    "image/%s": "%s",' "$name" "${reference##*@sha256:}")"$'\n'
done < <(jq -r '.images | to_entries | sort_by(.key)[] | [.key, .value] | @tsv' "$WORK/inputs.json")

# ---- 4. The compilation, without a network.

# The stage `image` is not taken from the layer cache: BuildKit finds the copy of that stage by
# the bytes of the file, so a commit whose node program has the bytes of an earlier build would
# get the layer of that build, with the time of that build (`rewrite-timestamp` lowers a time
# that is later than the commit time and leaves an earlier one). With `--no-cache` no stage is
# taken from the cache, and buildx takes one of the two options only.
CACHE_OPTIONS=(--no-cache-filter image)
[ -z "$NO_CACHE" ] || CACHE_OPTIONS=(--no-cache)

say "building the enclave image $NODE_IMAGE"
git -C "$SOURCE" archive --format=tar "$GIT_COMMIT" | docker buildx build \
    --builder "$SEALED" \
    --platform "$PLATFORM" \
    --provenance=false \
    --sbom=false \
    "${CACHE_OPTIONS[@]}" \
    --build-arg "CREDENTIAL_ENCLAVE_RELEASE=$RELEASE" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-context "vendor=$WORK/vendor" \
    "${CONTEXTS[@]}" \
    --file build/Dockerfile.enclave \
    --output "type=docker,name=$NODE_IMAGE,rewrite-timestamp=true" \
    - >&2

CONTAINER=$(docker create --platform "$PLATFORM" "$NODE_IMAGE")
docker cp "$CONTAINER:/credential-enclave" "$WORK/credential-enclave" >&2
docker rm "$CONTAINER" >/dev/null
CONTAINER=""
binary=$(sha256_stdin <"$WORK/credential-enclave")
say "node program: sha256 $binary"
# An image whose file has another time than the commit time would give measurements that
# another machine does not reproduce: the build stops instead.
stamped=$(file_time "$WORK/credential-enclave")
[ "$stamped" = "$SOURCE_DATE_EPOCH" ] ||
    fail "the node program of the enclave image has the time $stamped, not the commit time $SOURCE_DATE_EPOCH"

# ---- 5. The enclave image file and its measurements.

say "building the assembly tools $TOOLS_IMAGE"
docker buildx build \
    --builder "$FETCHER" \
    --platform "$PLATFORM" \
    --provenance=false \
    --sbom=false \
    --file "$PROCEDURE/Dockerfile.eif" \
    --output "type=docker,name=$TOOLS_IMAGE" \
    "$WORK/empty" >&2

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

pcr0=$(cat "$WORK/assembly/pcr0")
pcr1=$(cat "$WORK/assembly/pcr1")
pcr2=$(cat "$WORK/assembly/pcr2")
for value in "$pcr0" "$pcr1" "$pcr2"; do
    is_hex "$value" 96 || fail "nitro-cli gave a measurement that is not 96 hex digits"
done

# ---- 6. The outputs. The table of inputs names what the three measurements were made of.

buildkit_image=${BUILDKIT_IMAGE##*@sha256:}
cargo_image=${CARGO_IMAGE##*@sha256:}
amazonlinux_image=$(sed -n 's/^FROM [^ ]*@sha256:\([0-9a-f]\{64\}\).*/\1/p' "$PROCEDURE/Dockerfile.eif" | head -n 1)
for value in "$buildkit_image" "$cargo_image" "$amazonlinux_image" "$binary"; do
    is_hex "$value" 64 || fail "an input of the build has no SHA-256"
done

cp "$WORK/assembly/enclave.eif" "$OUT/enclave.eif"
{
    printf '{\n'
    printf '  "release": "%s",\n' "$RELEASE"
    printf '  "git_commit": "%s",\n' "$GIT_COMMIT"
    printf '  "pcr0": "%s",\n' "$pcr0"
    printf '  "pcr1": "%s",\n' "$pcr1"
    printf '  "pcr2": "%s",\n' "$pcr2"
    printf '  "inputs": {\n'
    printf '%s' "$INPUT_LINES"
    printf '    "image/buildkit": "%s",\n' "$buildkit_image"
    printf '    "image/cargo": "%s",\n' "$cargo_image"
    printf '    "image/amazonlinux": "%s",\n' "$amazonlinux_image"
    for file in rust-toolchain.toml Cargo.toml Cargo.lock build/Dockerfile.enclave build/inputs.json; do
        printf '    "file/%s": "%s",\n' "$file" "$(committed "$file" | sha256_stdin)"
    done
    for file in enclave-build.sh Dockerfile.vendor Dockerfile.eif; do
        printf '    "procedure/%s": "%s",\n' "$file" "$(sha256_stdin <"$PROCEDURE/$file")"
    done
    for blob in bzImage cmdline init linuxkit nsm.ko; do
        hash=$(awk -v name="$blob" '$2 == name { print $1 }' "$WORK/assembly/blobs.sha256")
        is_hex "$hash" 64 || fail "the blob $blob has no SHA-256"
        printf '    "blob/%s": "%s",\n' "$blob" "$hash"
    done
    printf '    "binary/credential-enclave": "%s"\n' "$binary"
    printf '  }\n'
    printf '}\n'
} >"$OUT/measurements.json"
jq -e . "$OUT/measurements.json" >/dev/null || fail "measurements.json is not JSON"

say "wrote $OUT/enclave.eif (sha256 $(sha256_stdin <"$OUT/enclave.eif"))"
say "wrote $OUT/measurements.json"
cat "$OUT/measurements.json"
