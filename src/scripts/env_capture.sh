#!/usr/bin/env bash
# Records the pinned software + hardware environment into results/env/environment.json
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/env
j() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
cpu_model=$(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2;exit}')
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "n/a")
turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || echo "n/a")
auth_v=$(docker compose exec -T sld-aiori pdns_server --version 2>&1 | grep -m1 -i 'PowerDNS Authoritative' || docker compose exec -T root pdns_server --version 2>&1 | grep -m1 -i 'PowerDNS Authoritative' || echo "not running")
rec_v=$(docker compose exec -T resolver pdns_recursor --version 2>&1 | grep -m1 -i 'PowerDNS Recursor' || echo "not running")
oqs_v=$(docker compose exec -T client python -c "import oqs,importlib.metadata as m;print('liboqs',oqs.oqs_version(),'liboqs-python',m.version('liboqs-python'),'dnspython',m.version('dnspython'),'pycryptodome',m.version('pycryptodome'),'cryptography',m.version('cryptography'))" 2>/dev/null | grep -v faulthandler || echo "not running")
imgs=$(docker images --format '{{.Repository}}:{{.Tag}}={{.ID}}' | grep pqcmtl | tr '\n' ' ')
source .env 2>/dev/null || true
cat > results/env/environment.json <<JSON
{
  "captured_at_utc": $(j "$(date -u +%FT%TZ)"),
  "host_os": $(j "$(. /etc/os-release; echo "$PRETTY_NAME")"),
  "kernel": $(j "$(uname -r)"),
  "cpu_model": $(j "$cpu_model"),
  "cpu_count": $(j "$(nproc)"),
  "memory_total": $(j "$(free -h | awk '/Mem:/{print $2}')"),
  "cpu_governor": $(j "$gov"),
  "turbo_disabled_or_boost": $(j "$turbo"),
  "docker": $(j "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"),
  "docker_compose": $(j "$(docker compose version --short 2>/dev/null)"),
  "cpuset_auth": $(j "${AUTH_CPUS:-1}"),
  "cpuset_resolver": $(j "${RESOLVER_CPUS:-2}"),
  "cpuset_client_and_bench": $(j "${CLIENT_CPUS:-3} / ${BENCH_CPUS:-3}"),
  "powerdns_auth": $(j "$auth_v"),
  "powerdns_recursor": $(j "$rec_v"),
  "pqc_stack": $(j "$oqs_v"),
  "images": $(j "$imgs"),
  "testbed_git_commit": $(j "$(git rev-parse --short HEAD 2>/dev/null || echo n/a)")
}
JSON
echo ">> wrote results/env/environment.json"; cat results/env/environment.json
