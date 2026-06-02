import subprocess
import secrets
import os
import sys
import re

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def isroot():
    if os.geteuid() != 0:
        print("✗ Bitte als root / mit sudo ausführen.")
        sys.exit(1)


def get_default_iface() -> str:
    r = run(["ip", "-6", "route", "show", "default"])
    for line in r.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    print("✗ Kein Default-Interface gefunden.")
    sys.exit(1)


def ensure_dummy_iface(name="ipwrap0") -> str:
    r = run(["ip", "link", "show", name])
    if r.returncode != 0:
        r = run(["ip", "link", "add", name, "type", "dummy"])
        if r.returncode != 0:
            print("✗ Konnte Interface nicht erstellen:", r.stderr.strip())
            sys.exit(1)
    run(["ip", "link", "set", name, "up"])
    return name


def expand_ipv6(addr: str) -> str:
    if "::" in addr:
        left, right = addr.split("::", 1)
        l = left.split(":") if left else []
        r = right.split(":") if right else []
        missing = 8 - len(l) - len(r)
        groups = l + ["0000"] * missing + r
    else:
        groups = addr.split(":")
    return ":".join(g.zfill(4) for g in groups)


def get_prefix(iface: str) -> str:
    r = run(["ip", "-o", "-6", "addr", "show", "dev", iface])
    for line in r.stdout.splitlines():
        if "scope global" not in line:
            continue
        m = re.search(r"inet6 ([0-9a-f:]+)/(\d+)", line)
        if not m:
            continue
        addr, plen = m.group(1), int(m.group(2))
        if plen > 64:
            continue
        full = expand_ipv6(addr)
        groups = full.split(":")
        return ":".join(groups[:4]) + ":"
    print(f"✗ Kein globales IPv6-Prefix auf Interface '{iface}' gefunden.")
    sys.exit(1)


def random_suffix() -> str:
    return ":".join(f"{secrets.randbits(16):04x}" for _ in range(4))


def generate_address(prefix: str) -> str:
    return prefix + random_suffix()


def current_addresses(iface: str) -> set[str]:
    r = run(["ip", "-o", "-6", "addr", "show", "dev", iface])
    addresses = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[3].split("/")[0]
            addresses.add(expand_ipv6(ip))
    return addresses


def add_address(iface: str, addr: str, ttl: int = None) -> bool:
    cmd = ["ip", "-6", "addr", "add", f"{addr}/64", "dev", iface]
    
    if ttl is not None:
        cmd.extend(["valid_lft", str(ttl), "preferred_lft", str(ttl)])
    
    r = run(cmd)
    if r.returncode != 0 and "File exists" not in r.stderr:
        print("[DEBUG ip error]", r.stderr.strip())
        
    return r.returncode == 0




