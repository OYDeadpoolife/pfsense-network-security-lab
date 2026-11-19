#!/usr/bin/env bash
# filterlog_summary.sh - summarise a pfSense firewall log: what was allowed, what was blocked, and by whom.
#
# Reads a log file (it never modifies it), prints a text summary or the parsed events as CSV.
# Needs only bash, awk, sort, uniq and head. See docs/log-analysis.md for how to read the result.
set -u
set -o pipefail

VERSION="1.0.0"
SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
AWK_BIN=${FILTERLOG_AWK:-awk}

usage() {
    cat <<USAGE
filterlog_summary.sh $VERSION - summarise a pfSense filter.log

Usage: filterlog_summary.sh --input FILE [--format text|csv] [--ip ADDRESS] [--top N]

  -i, --input FILE     log file, or - for standard input
  -f, --format FORMAT  text (default): a summary; csv: one row per firewall event
      --ip ADDRESS     only events whose source or destination is ADDRESS (an investigation pivot)
      --top N          rows in the "top" lists (default 10)
  -h, --help           show this help
      --version        show the version

Exit status: 0 success, 2 invalid options, 3 input problem.
USAGE
}

die() {
    local code=$1
    shift
    printf 'filterlog_summary.sh: error: %s\n' "$*" >&2
    exit "$code"
}

input=""
format=text
address=""
top=10
while [[ $# -gt 0 ]]; do
    case $1 in
        -i | --input) input=${2:?--input needs a value} && shift 2 ;;
        -f | --format) format=${2:?--format needs a value} && shift 2 ;;
        --ip) address=${2:?--ip needs a value} && shift 2 ;;
        --top) top=${2:?--top needs a value} && shift 2 ;;
        -h | --help)
            usage
            exit 0
            ;;
        --version)
            echo "filterlog_summary.sh $VERSION"
            exit 0
            ;;
        *) die 2 "unknown option: $1 (see --help)" ;;
    esac
done

[[ -n $input ]] || die 2 "no input given: use --input FILE"
[[ $format == text || $format == csv ]] || die 2 "--format must be text or csv, got '$format'"
[[ $top =~ ^[0-9]{1,3}$ && $top -ge 1 ]] || die 2 "--top must be a number between 1 and 999, got '$top'"
if [[ -n $address && ! $address =~ ^[0-9A-Fa-f:.]+$ ]]; then
    die 2 "--ip must be an IPv4 or IPv6 address, got '$address'"
fi
if [[ $input != - ]]; then
    [[ -e $input ]] || die 3 "input does not exist: $input"
    [[ -f $input && -r $input ]] || die 3 "input is not a readable file: $input"
fi
command -v "$AWK_BIN" >/dev/null 2>&1 || die 3 "awk not found: $AWK_BIN"

work=$(mktemp -d "${TMPDIR:-/tmp}/filterlog.XXXXXX") || die 3 "cannot create a temporary directory"
trap 'rm -rf -- "$work"' EXIT
events=$work/events.tsv
stats=$work/stats.txt

# "awk 1" copies the input and guarantees a final newline; the file is read through standard input
# because awk would treat a file name such as x=1 as a variable assignment.
if [[ $input == - ]]; then
    LC_ALL=C "$AWK_BIN" 1
else
    LC_ALL=C "$AWK_BIN" 1 <"$input"
fi | LC_ALL=C "$AWK_BIN" -v ip="$address" -f "$SCRIPT_DIR/filterlog.awk" >"$events" 2>"$stats" ||
    die 3 "could not read or parse the input"

if [[ $format == csv ]]; then
    printf 'time,host,rule,tracker,interface,action,direction,ip_version,protocol,src_ip,src_port,dst_ip,dst_port,detail\n'
    LC_ALL=C tr '\t' ',' <"$events"
    exit 0
fi

stat_value() {
    awk -F '\t' -v name="$1" '$2 == name { print $3 }' "$stats"
}

printf 'pfSense firewall log summary\n'
printf '  Input        : %s\n' "$input"
[[ -n $address ]] && printf '  Filter       : events involving %s\n' "$address"
printf '  Lines read   : %s (not filterlog: %s, malformed: %s)\n' "$(stat_value lines_total)" "$(stat_value lines_not_filterlog)" "$(stat_value lines_malformed)"
printf '  Events       : %s\n' "$(stat_value events)"

printf '\nAction by interface (interface names are the real NICs, for example em0 = WAN in the lab)\n'
awk -F '\t' '{ count[$5 "\t" $6]++ } END { for (key in count) print key "\t" count[key] }' "$events" | LC_ALL=C sort |
    awk -F '\t' '{ printf "  %-6s %-6s %6d\n", $1, $2, $3 }'

printf '\nTop %s blocked sources\n' "$top"
awk -F '\t' '$6 == "block" { print $10 }' "$events" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n "$top" |
    awk '{ printf "  %6d  %s\n", $1, $2 }'

printf '\nTop %s blocked destination ports\n' "$top"
awk -F '\t' '$6 == "block" { print $9 "/" $13 }' "$events" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n "$top" |
    awk '{ printf "  %6d  %s\n", $1, $2 }'

printf '\nAllowed connections to non-private destinations (what internal hosts reached on the Internet)\n'
awk -F '\t' '
    function is_private(a) { return a ~ /^10\./ || a ~ /^192\.168\./ || a ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ || a ~ /^127\./ }
    $6 == "pass" && is_private($10) && !is_private($12) { print $10 " -> " $12 ":" $13 }
' "$events" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n "$top" | awk '{ printf "  %6d  %s %s %s\n", $1, $2, $3, $4 }'

printf '\nRule hits (rule number, tracker ID, action)\n'
awk -F '\t' '{ print $3 "\t" $4 "\t" $6 }' "$events" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n "$top" |
    awk '{ printf "  %6d  rule %-4s tracker %-12s %s\n", $1, $2, $3, $4 }'
