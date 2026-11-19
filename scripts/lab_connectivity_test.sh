#!/usr/bin/env bash
# lab_connectivity_test.sh - run the SAFE connectivity tests of the pfSense lab from one machine and compare with the design.
#
# This is NOT a scanner. It tries one connection (or one ping) per line of the expectations file, one target
# at a time, and only to addresses inside the lab ranges 10.10.0.0/16 and 203.0.113.0/24. It refuses to run
# against anything else. Run it only inside your own isolated lab, never against a network you do not own.
set -u
set -o pipefail

VERSION="1.0.0"
SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1

usage() {
    cat <<USAGE
lab_connectivity_test.sh $VERSION - safe firewall tests for the pfSense lab

Usage: lab_connectivity_test.sh --zone LAN|DMZ|MGMT|WAN --confirm-lab [options]

  -z, --zone ZONE         run the tests whose source_zone is ZONE (run the script on a machine in that zone)
      --confirm-lab       you confirm that this machine is in YOUR isolated lab (required to send any traffic)
  -e, --expectations FILE the test list (default: samples/lab-expectations.csv)
  -t, --timeout SECONDS   wait this long for each test (default 3)
      --dry-run           show what would be tested, send nothing
      --list              list the tests of the zone and exit
      --allow-loopback    also accept 127.0.0.0/8 targets (used by the self-tests of this repository)
  -h, --help              show this help
      --version           show the version

Exit status: 0 all tests matched the expectation, 1 at least one did not, 2 invalid options, 3 input problem.
USAGE
}

die() {
    local code=$1
    shift
    printf 'lab_connectivity_test.sh: error: %s\n' "$*" >&2
    exit "$code"
}

zone=""
expectations=$SCRIPT_DIR/../samples/lab-expectations.csv
timeout_seconds=3
confirmed=0
dry_run=0
list_only=0
allow_loopback=0
while [[ $# -gt 0 ]]; do
    case $1 in
        -z | --zone) zone=${2:?--zone needs a value} && shift 2 ;;
        -e | --expectations) expectations=${2:?--expectations needs a value} && shift 2 ;;
        -t | --timeout) timeout_seconds=${2:?--timeout needs a value} && shift 2 ;;
        --confirm-lab) confirmed=1 && shift ;;
        --dry-run) dry_run=1 && shift ;;
        --list) list_only=1 && shift ;;
        --allow-loopback) allow_loopback=1 && shift ;;
        -h | --help)
            usage
            exit 0
            ;;
        --version)
            echo "lab_connectivity_test.sh $VERSION"
            exit 0
            ;;
        *) die 2 "unknown option: $1 (see --help)" ;;
    esac
done

[[ $zone =~ ^(LAN|DMZ|MGMT|WAN)$ ]] || die 2 "--zone must be LAN, DMZ, MGMT or WAN"
[[ $timeout_seconds =~ ^[0-9]{1,2}$ && $timeout_seconds -ge 1 ]] || die 2 "--timeout must be 1-99 seconds"
[[ -f $expectations && -r $expectations ]] || die 3 "expectations file not found or not readable: $expectations"

# The only addresses this script will ever contact.
target_is_in_lab() {
    local ip=$1
    [[ $ip =~ ^10\.10\.([0-9]{1,3})\.([0-9]{1,3})$ || $ip =~ ^203\.0\.113\.([0-9]{1,3})$ ]] && return 0
    ((allow_loopback)) && [[ $ip =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && return 0
    return 1
}

octets_valid() {
    local part
    local IFS=.
    for part in $1; do
        ((10#$part <= 255)) || return 1
    done
}

# Returns success if the connection or ping worked.
run_test() {
    local protocol=$1 ip=$2 port=$3
    case $protocol in
        tcp) nc -z -w "$timeout_seconds" "$ip" "$port" >/dev/null 2>&1 ;;
        icmp)
            if [[ $(uname -s) == Darwin ]]; then
                ping -c 1 -t "$timeout_seconds" "$ip" >/dev/null 2>&1
            else
                ping -c 1 -W "$timeout_seconds" "$ip" >/dev/null 2>&1
            fi
            ;;
    esac
}

total=0
failed=0
matched_any=0
tests=()
while IFS=, read -r test_id row_zone description protocol ip port expected reason; do
    [[ -z $test_id || $test_id == \#* || $test_id == test_id ]] && continue
    [[ $row_zone == "$zone" ]] || continue
    matched_any=1
    [[ $protocol == tcp || $protocol == icmp ]] || die 3 "$test_id: protocol must be tcp or icmp"
    [[ $port =~ ^[0-9]{1,5}$ && $port -le 65535 ]] || die 3 "$test_id: invalid port '$port'"
    [[ $expected == allow || $expected == block ]] || die 3 "$test_id: expected must be allow or block"
    if ! target_is_in_lab "$ip" || ! octets_valid "$ip"; then
        die 2 "$test_id: refusing target $ip (only 10.10.0.0/16 and 203.0.113.0/24 are allowed)"
    fi
    tests+=("$test_id|$description|$protocol|$ip|$port|$expected|$reason")
done <"$expectations"

((matched_any)) || die 3 "no tests for zone $zone in $expectations"

if ((list_only || dry_run)); then
    for entry in "${tests[@]}"; do
        IFS='|' read -r test_id description protocol ip port expected reason <<<"$entry"
        printf '%s  %-4s %s %s:%s  expect %s  (%s)\n' "$test_id" "$protocol" "$description" "$ip" "$port" "$expected" "$reason"
    done
    ((dry_run)) && echo "dry run: nothing was sent."
    exit 0
fi

((confirmed)) || die 2 "add --confirm-lab to confirm that you are in your own isolated lab"
command -v nc >/dev/null 2>&1 || die 3 "nc (netcat) is needed for the TCP tests"

printf 'Running %d test(s) from zone %s (timeout %ss each)\n' "${#tests[@]}" "$zone" "$timeout_seconds"
for entry in "${tests[@]}"; do
    IFS='|' read -r test_id description protocol ip port expected reason <<<"$entry"
    total=$((total + 1))
    actual=block
    if run_test "$protocol" "$ip" "$port"; then
        actual=allow
    fi
    verdict=PASS
    if [[ $actual != "$expected" ]]; then
        verdict=FAIL
        failed=$((failed + 1))
    fi
    printf '%-4s %s  %s %s:%s  expected=%s actual=%s\n' "$verdict" "$test_id" "$protocol" "$ip" "$port" "$expected" "$actual"
done
printf '\n%d test(s), %d matched the design, %d did not.\n' "$total" "$((total - failed))" "$failed"
((failed == 0))
