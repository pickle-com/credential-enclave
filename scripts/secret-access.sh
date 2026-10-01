#!/usr/bin/env bash
#
# Rule E2 of the egress policy (docs/egress-policy.md): the functions that read the bytes of a
# secret are a closed list, and so are the functions that call one of the five sinks.
#
#   scripts/secret-access.sh           prints the two lists, as the source has them
#   scripts/secret-access.sh --check   compares them with egress/secret-access.tsv and
#                                      egress/sink-callers.tsv and fails when they differ
#
# The first list: every function of the node source that names `expose_secret`. The bytes of a
# secret are read through `Secret::expose_secret` and through nothing else: the field of
# `Secret` is private to protocol/src/secret.rs. For that file the list holds the functions
# that touch the private fields. So the list is every place of the node program that can read
# a secret.
#
# The second list: every function of the node source that calls a sink. A call is the name of
# the sink function in front of `(`, where the name is not the end of a longer name. It is
# found after a path (`record::seal(`) and where the name is imported and stands alone
# (`seal(`).
#
#   K1  seal              `record::seal`: a secret leaves as the ciphertext of a record
#   K2  seal_transfer     user keys leave inside the seal to a verified peer node
#   K3  send_to_provider  a request, with its secrets, goes to a provider over TLS
#   K4  hand_out          a vault value becomes part of the response of `release`
#   K5  send_to_log_store a signed log entry goes to the log store over TLS, in a request
#                         signed with the credentials of the operator
#
# The node source is protocol/src and enclave/src without the code that is compiled for tests
# only and without the vector generator (`protocol/src/bin/`), which is a separate program.
# The code for tests only is `enclave/src/tests/`, `enclave/src/testing.rs`, and in every file
# its test module: the lines from a `#[cfg(test)]` at the start of a line that is followed by
# `mod tests {` or `pub mod tests {`. A test module that lies in a file of its own
# (`#[cfg(test)]` followed by `mod tests;`) does not end the reading of the file that declares
# it. A file is read up to its test module, so the test module is the last item of a file: the
# script fails when a line that is neither empty nor a comment follows it. A comment line
# names no function and is no use.
#
# `--check` also counts, apart from the reading that makes the two lists, how often the node
# source names `expose_secret` and how often it calls each sink, and fails when a count is not
# the sum of its list. It fails as well when a line gives a sink another name (`seal as`): a
# call under that name would not be found.
#
# egress/secret-access.tsv holds one line per function: file, function, uses, use, note. The
# first three columns are what this script prints. `use` is one of:
#
#   K1 K2 K3 K4 K5   the function is that sink
#   in-node       the bytes are used inside the node: the result is a secret again, a public
#                 key, a signature, a ciphertext, or the outcome of a check
#   declassify    the result leaves in the clear and is one of the declassified values of
#                 docs/egress-policy.md
#
# egress/sink-callers.tsv holds one line per function: sink, file, function, calls, note.

set -euo pipefail

cd "$(dirname "$0")/.."

ACCESS_LIST="egress/secret-access.tsv"
CALLER_LIST="egress/sink-callers.tsv"

# The accessor of a secret.
ACCESSOR="expose_secret"

# The sinks: the sink, the name of its function, and how a call of it is written. `function`:
# after a path or alone. `method`: also after a `.`. K1 is `function` because `seal` is also the
# name of the method `OauthPlaintext::seal`, the one function that calls K1: `.seal(` is a call
# of that method. The patterns below are made from this table and from nothing else.
SINKS='K1 seal function
K2 seal_transfer method
K3 send_to_provider method
K4 hand_out method
K5 send_to_log_store method'

SINK_NAMES=$(printf '%s\n' "$SINKS" | cut -d ' ' -f 2 | paste -s -d '|' -)

# The lines that define the accessor or a sink: `fn name(` and `fn name<`. A definition is
# not a use.
DEFINITIONS="fn ($ACCESSOR|$SINK_NAMES)[(<]"

# A line that gives a sink another name: `use ...::seal as other;`.
RENAMES="(^|[^A-Za-z0-9_])($SINK_NAMES) as "

# Writes a failure to the standard error.
fail() {
    echo "secret-access: $*" >&2
}

# The pattern of a call of the sink function `$1`, written in the way `$2`.
call_pattern() {
    case "$2" in
        function) printf '(^|[^A-Za-z0-9_.])%s[(]' "$1" ;;
        method) printf '(^|[^A-Za-z0-9_])%s[(]' "$1" ;;
        *)
            fail "unknown way '$2' to call the sink $1"
            exit 1
            ;;
    esac
}

node_sources() {
    find protocol/src enclave/src -name '*.rs' \
        -not -path 'protocol/src/bin/*' \
        -not -path 'enclave/src/tests/*' \
        -not -path 'enclave/src/testing.rs' \
        | LC_ALL=C sort
}

# Prints `file<TAB>function<TAB>count` for every function of the file `$1` whose body matches
# the pattern `$2`, up to the test module of the file. A method is named `Type::function`.
functions_matching() {
    awk -v file="$1" -v pattern="$2" -v definitions="$DEFINITIONS" '
        # The test module of a file: everything from here on is test code. The declaration
        # of a test module that lies in another file (`mod tests;`) is not the end.
        /^#\[cfg\(test\)\]$/ { pending = 1; next }
        pending && /^(pub )?mod tests [{]$/ { exit }
        { pending = 0 }
        # A comment names no function and is no use.
        /^[ ]*\/\// { next }
        # rustfmt puts every top-level item at column 0 and every method one level in.
        /^impl/ {
            type = $0
            sub(/^impl(<[^>]*>)? /, "", type)
            if (type ~ / for /) sub(/^.* for /, "", type)
            sub(/[^A-Za-z0-9_].*$/, "", type)
        }
        /^}/ { type = "" }
        match($0, /fn [a-z_0-9]+/) {
            name = substr($0, RSTART + 3, RLENGTH - 3)
            if (type != "" && $0 ~ /^ /) name = type "::" name
        }
        # The definitions of the accessor and of the sinks are not uses.
        $0 ~ definitions { next }
        {
            line = $0
            uses = gsub(pattern, "", line)
            if (uses > 0) {
                if (!(name in count)) names[++n] = name
                count[name] += uses
            }
        }
        END {
            for (i = 1; i <= n; i++) printf "%s\t%s\t%d\n", file, names[i], count[names[i]]
        }
    ' "$1"
}

# The functions that name the accessor.
secret_uses() {
    node_sources | while read -r file; do
        functions_matching "$file" "$ACCESSOR"
    done
}

# The functions of the secret module itself that touch the private fields: the field of
# `Secret` and the two private keys of `NodeKeys`.
secret_fields() {
    functions_matching protocol/src/secret.rs '(self|secret)[.]0|self[.](sign|seal)[^(_a-z]'
}

sink_callers() {
    printf '%s\n' "$SINKS" | while read -r sink name way; do
        pattern=$(call_pattern "$name" "$way")
        node_sources | while read -r file; do
            functions_matching "$file" "$pattern" | sed "s/^/$sink	/"
        done
    done
}

# Prints `file:line` for every line after the test module of the file `$1` that is neither
# empty nor a comment. `functions_matching` does not read these lines.
code_after_tests() {
    awk -v file="$1" '
        closed && !/^[ ]*$/ && !/^[ ]*\/\// { printf "%s:%d\n", file, NR }
        inside && $0 == "}" { inside = 0; closed = 1 }
        pending && /^(pub )?mod tests [{]$/ { inside = 1 }
        { pending = ($0 == "#[cfg(test)]") }
    ' "$1"
}

# Fails when a file of the node source has code after its test module.
tests_are_last() {
    local misplaced
    misplaced=$(node_sources | while read -r file; do code_after_tests "$file"; done)
    if [ -n "$misplaced" ]; then
        fail "code follows the test module of a file, where this script does not read it"
        printf '%s\n' "$misplaced" >&2
        return 1
    fi
}

# Prints the lines of the file `$1` outside its test module, without the comment lines. The
# counts of `--check` are made on these lines, apart from the reading of `functions_matching`.
node_lines() {
    awk '
        inside { if ($0 == "}") inside = 0; next }
        held != "" {
            if ($0 ~ /^(pub )?mod tests [{]$/) { held = ""; inside = 1; next }
            print held
            held = ""
        }
        $0 == "#[cfg(test)]" { held = $0; next }
        /^[ ]*\/\// { next }
        { print }
        END { if (held != "") print held }
    ' "$1"
}

# How often the node source matches the pattern `$1`, outside the definitions.
count_in_source() {
    node_sources | while read -r file; do
        node_lines "$file"
    done | { grep -E -v "$DEFINITIONS" || true; } | { grep -E -o "$1" || true; } \
        | wc -l | tr -d ' '
}

# The sum of the column `$1` of the lines on the standard input.
sum_of_column() {
    awk -F '\t' -v column="$1" '{ sum += $column } END { print sum + 0 }'
}

# Compares the columns of a committed list that this script computes with the source.
compare() {
    local list="$1" columns="$2" found="$3" name="$4"
    if [ ! -f "$list" ]; then
        fail "$list is missing"
        return 1
    fi
    local listed
    listed=$(grep -v '^#' "$list" | grep -v '^$' | cut -f "$columns")
    if [ "$listed" != "$found" ]; then
        fail "$name differ from $list"
        diff <(printf '%s\n' "$listed") <(printf '%s\n' "$found") >&2 || true
        fail "'<' is listed, '>' is in the source"
        return 1
    fi
    if grep -v '^#' "$list" | grep -v '^$' \
        | awk -F '\t' 'NF != 5 || $5 == "" { bad = 1 } END { exit !bad }'; then
        fail "a line of $list lacks one of its five columns"
        return 1
    fi
}

# Fails when a count made on the lines of the node source is not the sum of its list.
cross_check() {
    local uses="$1" callers="$2" failed=0 counted listed renamed
    counted=$(count_in_source "$ACCESSOR")
    listed=$(printf '%s\n' "$uses" | sum_of_column 3)
    if [ "$counted" != "$listed" ]; then
        fail "the node source names $ACCESSOR $counted times," \
            "and the functions of the list account for $listed"
        failed=1
    fi
    while read -r sink name way; do
        counted=$(count_in_source "$(call_pattern "$name" "$way")")
        listed=$(printf '%s\n' "$callers" | awk -F '\t' -v sink="$sink" '$1 == sink' \
            | sum_of_column 4)
        if [ "$counted" != "$listed" ]; then
            fail "the node source calls the sink $sink ($name) $counted times," \
                "and the functions of the list account for $listed"
            failed=1
        fi
    done <<EOF
$SINKS
EOF
    renamed=$(node_sources | while read -r file; do
        node_lines "$file" | { grep -E "$RENAMES" || true; } | sed "s|^|$file: |"
    done)
    if [ -n "$renamed" ]; then
        fail "a sink gets another name, and a call under that name is not found"
        printf '%s\n' "$renamed" >&2
        failed=1
    fi
    return "$failed"
}

case "${1:-}" in
    "")
        tests_are_last
        secret_uses
        secret_fields
        sink_callers
        ;;
    --check)
        failed=0
        tests_are_last || failed=1
        uses=$(secret_uses)
        access=$(printf '%s\n%s' "$uses" "$(secret_fields)")
        callers=$(sink_callers)
        compare "$ACCESS_LIST" 1-3 "$access" "the functions that read a secret" || failed=1
        compare "$CALLER_LIST" 1-4 "$callers" "the functions that call a sink" || failed=1
        for use in $(grep -v '^#' "$ACCESS_LIST" | grep -v '^$' | cut -f 4 | LC_ALL=C sort -u); do
            case "$use" in
                K1 | K2 | K3 | K4 | K5 | in-node | declassify) ;;
                *)
                    fail "unknown use '$use' in $ACCESS_LIST"
                    failed=1
                    ;;
            esac
        done
        cross_check "$uses" "$callers" || failed=1
        if [ "$failed" -ne 0 ]; then
            exit 1
        fi
        readers=$(printf '%s\n' "$access" | wc -l | tr -d ' ')
        calling=$(printf '%s\n' "$callers" | wc -l | tr -d ' ')
        echo "secret-access: $readers functions read a secret and $calling functions call a sink," \
            "all listed"
        ;;
    *)
        echo "usage: scripts/secret-access.sh [--check]" >&2
        exit 2
        ;;
esac
