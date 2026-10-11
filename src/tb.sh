#!/usr/bin/env bash
# PS-036 PQC DNSSEC MTL testbed - orchestration.  Run ./tb.sh help
set -euo pipefail
cd "$(dirname "$0")"

# Auto-detect host directory for Docker volume mounts (supports DooD inside UI container)
if [ -z "${HOST_DIR:-}" ]; then
  if [ -f /.dockerenv ] && command -v docker >/dev/null 2>&1; then
    DETECTED_HOST_DIR=$(docker inspect "${HOSTNAME:-pqcmtl-ui}" --format '{{range .Mounts}}{{if eq .Destination "/work"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)
    [ -n "$DETECTED_HOST_DIR" ] && HOST_DIR="$DETECTED_HOST_DIR"
  fi
  if [ -z "${HOST_DIR:-}" ]; then
    HOST_DIR="$(cd "$(dirname "$0")" && pwd)"
  fi
  export HOST_DIR
fi

if [ -f .env ]; then
  if grep -q "^HOST_DIR=" .env 2>/dev/null; then
    sed -i "s|^HOST_DIR=.*|HOST_DIR=${HOST_DIR}|" .env
  else
    echo "HOST_DIR=${HOST_DIR}" >> .env
  fi
fi

DC="docker compose"
C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'; C_OFF=$'\e[0m'
say()  { echo "${C_GRN}==>${C_OFF} $*"; }
warn() { echo "${C_YEL}!!${C_OFF} $*"; }
die()  { echo "${C_RED}xx${C_OFF} $*"; exit 1; }

tools() { $DC run --rm -T --user "$(id -u):$(id -g)" -e HOME=/tmp tools "$@"; }
client() { $DC exec -T client "$@"; }

current_mode() { python3 -c "import json;m=json.load(open('zones/sign_stats.json'))['meta'];print(m['mode'],m['dataset'],m['hosts'])" 2>/dev/null || echo "none"; }

wait_ready() {
  say "waiting for authoritative servers to load their zones ..."
  for i in $(seq 1 180); do
    ok=0
    for ipz in "172.30.53.10 ." "172.30.53.20 test." "172.30.53.30 aiori3.test."; do
      set -- $ipz
      $DC exec -T root dig +short +time=1 +tries=1 @"$1" "$2" SOA 2>/dev/null | grep -q . && ok=$((ok+1))
    done
    [ "$ok" = 3 ] && { say "root, test. and aiori3.test. are serving"; return 0; }
    sleep 2
  done
  $DC logs --tail 30 root tld-lab sld-aiori
  die "authoritative servers not ready"
}

flush() { curl_out=$($DC exec -T client curl -s -X PUT -H 'X-API-Key: labkey' \
            "http://172.30.53.53:8082/api/v1/servers/localhost/cache/flush?domain=.&subtree=true" || true)
          say "resolver cache flushed: $curl_out"; }

cmd_setup() {
  command -v docker >/dev/null || die "docker not installed - see README step 1"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin missing - see README step 1"
  n=$(nproc)
  if [ "$n" -lt 4 ]; then
    warn "only $n CPUs: using shared cpusets (results will be noisier)"
    sed -i "s/^AUTH_CPUS=.*/AUTH_CPUS=0/; s/^RESOLVER_CPUS=.*/RESOLVER_CPUS=0/; s/^CLIENT_CPUS=.*/CLIENT_CPUS=$((n-1))/; s/^BENCH_CPUS=.*/BENCH_CPUS=$((n-1))/" .env
  fi
  mkdir -p zones keys results config
  say "building images (first build compiles liboqs; takes a few minutes) ..."
  $DC --profile tools build
  say "generating lab root hints from IANA named.root ..."
  tools python -m pqcdns.hints config
  say "setup done. Next: ./tb.sh sign mtl small && ./tb.sh up && ./tb.sh test"
}

cmd_sign() {
  local mode=${1:?mode: mldsa44|mtl} ds=${2:-small}
  say "signing hierarchy: mode=$mode dataset=$ds"
  tools python -m pqcdns.signer sign --mode "$mode" --dataset "$ds" --out zones --keys keys
}

cmd_up() {
  [ -f zones/root.zone ] || die "no signed zones - run ./tb.sh sign <mode> <dataset> first"
  [ -f config/lab-root.hints ] || die "no root hints - run ./tb.sh setup"
  say "starting containers (zones: $(current_mode))"
  $DC up -d --force-recreate root tld-lab sld-aiori
  wait_ready
  $DC up -d resolver client ui
  sleep 2; flush
  $DC ps
  say "Workbench UI ready at: http://localhost:8080/"
}

cmd_ui() {
  say "starting Workbench UI container..."
  $DC up -d ui
  say "Workbench UI ready at: http://localhost:8080/"
}

cmd_reload() {
  say "reloading authoritative servers with current zones: $(current_mode)"
  $DC up -d --force-recreate root tld-lab sld-aiori
  wait_ready; flush
}

cmd_test() {
  say "1) iterative resolution through the lab recursor (dig from the client container)"
  client dig +dnssec +multi host00001.aiori3.test A | sed -n '/ANSWER SECTION/,/^$/p' | cut -c1-110
  client dig +dnssec test. DS | grep -E "status|DS|RRSIG" | cut -c1-110
  say "2) delegation chain (root -> test -> aiori3.test) as seen by dig +trace against the lab root"
  client dig +trace +nodnssec @172.30.53.10 www.aiori3.test A | grep -vE "^;|^$" | cut -c1-100
  say "3) full PQC chain-of-trust validation (trust anchor -> root -> test -> aiori3.test)"
  client python -m pqcdns.validator host00001.aiori3.test www.aiori3.test | grep -v faulthandler
}

cmd_bench_crypto() { tools python -m pqcdns.bench_crypto --out results --trials "${1:-5}"; }
cmd_bench_endurance() { tools python -m pqcdns.bench_endurance --out results --runs "${1:-200}"; }
cmd_bench_dns() { client python -m pqcdns.bench_dns --trials "${1:-5}" --queries "${2:-300}" "${@:3}"; }
cmd_report() { tools python -m pqcdns.report --results results; say "open results/REPORT.md"; }

cmd_evolve() {
  local add=${1:-50}
  say "evolving the signed series: +$add host RRsets (MTL: node set grows, new ladder, condensed sigs refreshed)"
  tools python -m pqcdns.signer evolve --add "$add" --out zones --keys keys
  cmd_reload
}

cmd_demo_evolve() {
  [ "$(current_mode | cut -d' ' -f1)" = mtl ] || die "demo-evolve needs MTL zones: ./tb.sh sign mtl small && ./tb.sh up"
  rm -f results/verifier-state.json
  say "A) cold verifier validates two names and keeps the verified ladders"
  client python -m pqcdns.validator host00005.aiori3.test host00050.aiori3.test --save-state /results/verifier-state.json | grep -E "SECURE|BOGUS|ladder_fetches\""
  cmd_evolve 25
  hosts=$(current_mode | cut -d' ' -f3)
  say "B) same names after the zone evolved - verifier re-uses its OLD ladders (backward compatibility)"
  client python -m pqcdns.validator host00005.aiori3.test host00050.aiori3.test --load-state /results/verifier-state.json | grep -E "SECURE|BOGUS|loaded|ladder_fetches\""
  say "C) a NEW record (beyond the old ladder) -> exactly one new signed ladder is fetched"
  client python -m pqcdns.validator "host$(printf %05d "$hosts").aiori3.test" --load-state /results/verifier-state.json | grep -E "SECURE|BOGUS|ladder_fetches\""
}

cmd_bench_all() {
  local trials=${TRIALS:-5} queries=${QUERIES:-300}
  cmd_env || true
  cmd_bench_crypto "$trials"
  for ds in small medium large; do
    for mode in mldsa44 mtl; do
      cmd_sign "$mode" "$ds"
      if $DC ps --status running | grep -q resolver; then cmd_reload; else cmd_up; fi
      cmd_bench_dns "$trials" "$queries"
      [ "$mode" = mtl ] && cmd_bench_dns "$trials" "$queries" --no-ladder-cache
    done
  done
  cmd_bench_endurance "${RUNS:-200}"
  cmd_env || true
  cmd_report
}

cmd_env() { scripts/env_capture.sh; }
cmd_status() { echo "zones: $(current_mode)"; $DC ps; }
cmd_logs() { $DC logs --tail "${2:-50}" "${1:-resolver}"; }
cmd_shell() { $DC exec client bash; }
cmd_down() { $DC down; }
cmd_clean() { $DC down -v --remove-orphans; rm -rf zones/* keys/*; say "zones and keys removed (results kept)"; }

cmd_help() { cat <<EOF
PS-036 PQC DNSSEC MTL testbed

  ./tb.sh setup                      check docker, build images, create lab root hints
  ./tb.sh sign <mldsa44|mtl> [small|medium|large]   sign root/test/aiori3.test (ZSK=PQC, KSK=ECDSA)
  ./tb.sh up                         start root, tld-lab, sld-aiori, resolver, client
  ./tb.sh ui                         start containerized Workbench UI (port 8080)
  ./tb.sh test                       dig + dig +trace + PQC chain validation from the client
  ./tb.sh reload                     reload auth servers after re-signing, flush resolver
  ./tb.sh dig <args>  |  ./tb.sh validate <names..>   run in the client container
  ./tb.sh evolve [N]                 add N RRsets to the signed series (MTL condensation)
  ./tb.sh demo-evolve                live backward-compatibility demo (MTL)
  ./tb.sh bench-crypto [trials]      offline sign/verify benchmark, 3 dataset sizes, both modes
  ./tb.sh bench-dns [trials] [queries] [--no-ladder-cache]   live workload for current zones
  ./tb.sh bench-endurance [runs]     ladder endurance: measured vs analytical (paper 7.1)
  ./tb.sh bench-all                  EVERYTHING (env, crypto, 3 sizes x 2 modes DNS, endurance, report)
  ./tb.sh report                     build results/REPORT.md + figures
  ./tb.sh env | status | logs [svc] | shell | down | clean
EOF
}

sub=${1:-help}; shift || true
case "$sub" in
  setup|sign|up|reload|test|evolve|report|env|status|logs|shell|down|clean|help|ui) "cmd_$sub" "$@";;
  flush) flush;;
  dig) client dig "$@";;
  validate) client python -m pqcdns.validator "$@";;
  demo-evolve) cmd_demo_evolve;;
  bench-crypto) cmd_bench_crypto "$@";;
  bench-dns) cmd_bench_dns "$@";;
  bench-endurance) cmd_bench_endurance "$@";;
  bench-all) cmd_bench_all;;
  *) cmd_help; exit 1;;
esac
