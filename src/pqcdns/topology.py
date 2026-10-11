"""Lab topology. IPs can be overridden with env vars (used for loopback smoke tests)."""
import os

ROOT_IP = os.environ.get("ROOT_IP", "172.30.53.10")
TLD_IP = os.environ.get("TLD_IP", "172.30.53.20")
SLD_IP = os.environ.get("SLD_IP", "172.30.53.30")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "172.30.53.53")
RESOLVER_API = os.environ.get("RESOLVER_API", f"http://{RESOLVER_IP}:8082")
RESOLVER_API_KEY = os.environ.get("RESOLVER_API_KEY", "labkey")

ROOT_NS = "a.root-servers.lab."
TLD_NS = "ns1.nic.test."
SLD_NS = "ns1.aiori3.test."
SLD_DOMAIN = "aiori3.test."

TTL = 3600
DATASETS = {"small": 100, "medium": 1000, "large": 10000}   # host RRsets in aiori3.test
