#!/usr/bin/env python3
"""Lab-only measurement driver for the history filter scale study
(docs/operations/lab-history-scale-study.md). Disposable data only.

Runs every case with the management API's SQL text, as a login holding only
trust_api_reader, through the security-barrier views and the server-owned
CA grant:
  warm  pg_stat_statements reset, one warm-up run, then 5 timed runs; reports
        mean/min/max execution time and shared buffers hit/read per call;
  cold  PostgreSQL restarted and the OS page cache dropped before each case,
        then one EXPLAIN (ANALYZE, BUFFERS);
  plan  one EXPLAIN (ANALYZE, BUFFERS) per case, written next to the results.
Usage (as root, with a disposable cluster that preloads pg_stat_statements):
  python3 -I scripts/lab/history_scale_study.py --db scale_1m --out DIR [--cold]
Connection: 127.0.0.1:55442; owner trust_bench (trust auth), reader login
scale_reader (created here, member of trust_api_reader only).
"""
import argparse
import json
import pathlib
import subprocess
import time

HOST, PORT, OWNER, READER = "127.0.0.1", "55442", "trust_bench", "scale_reader"
DATA = "/var/lib/postgresql/hqp-bench/data"
A = "dddddddd-0000-4000-8000-0000000000a1"
U = "dddddddd-0000-4000-8000-0000000000c1"
ISS, SUB = "https://issuer.scale.invalid", "reader"

SELECT = (
    "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,"
    "subject_cn,not_before,not_after,san_dns FROM management_certificate WHERE ca_id='{ca}' "
    "AND EXISTS (SELECT 1 FROM management_reader_scope WHERE issuer='{iss}' AND subject='{sub}' "
    "AND ca_id='{ca}') AND ({t}::text IS NULL OR (signed_at, request_id) < ({t}, {i}))"
)
ORDER = " ORDER BY signed_at DESC, request_id DESC LIMIT 101"
CN = " AND lower(subject_cn) LIKE '{}' ESCAPE '\\'"
SAN = " AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = '{}')"
NA = " AND not_after < '{}'"

FILTERS = {
    "none": "",
    "CN-strong": CN.format("svc-%"),
    "CN-medium": CN.format("app-%"),
    "CN-null": CN.format("zzz-%"),
    "SAN-strong": SAN.format("pool-7.lab.invalid"),
    "SAN-medium": SAN.format("grp-3.lab.invalid"),
    "SAN-null": SAN.format("absent.lab.invalid"),
    "NA-strong": NA.format("2025-01-01T17:30:00.000Z"),
    "NA-medium": NA.format("2025-03-14T00:00:00.000Z"),
    "NA-null": NA.format("2024-12-01T00:00:00.000Z"),
    "ALL-strong": CN.format("app-%") + SAN.format("pool-7.lab.invalid"),
    "ALL-medium": CN.format("app-%") + SAN.format("grp-3.lab.invalid"),
    "ALL-null": CN.format("app-%") + SAN.format("absent.lab.invalid") + NA.format("2025-03-14T00:00:00.000Z"),
}
# (case, filter, cursor position)
CASES = [("page1", "none", "first"), ("middle", "none", "middle"), ("end", "none", "end")]
CASES += [(f, f, "first") for f in FILTERS if f != "none"]
CASES += [("SAN-medium-middle", "SAN-medium", "middle"), ("SAN-medium-end", "SAN-medium", "end")]


def psql(db, sql, user=OWNER, extra=()):
    out = subprocess.run(
        ["psql", "-h", HOST, "-p", PORT, "-U", user, "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
         *extra, "-d", db, "-c", sql],
        check=True, capture_output=True, text=True, env={"PGPASSWORD": "test-only-not-secret"})
    return out.stdout


def reader_url(db):
    return f"postgresql://{READER}:test-only-not-secret@{HOST}:{PORT}/{db}"


def ensure_reader(db):
    psql(db, f"""DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{READER}') THEN
               CREATE ROLE {READER} LOGIN PASSWORD 'test-only-not-secret'; END IF; END$$;
               GRANT trust_api_reader TO {READER};""")
    # The login holds no other role and no table privilege of its own.
    roles = psql(db, f"SELECT string_agg(b.rolname, ',') FROM pg_auth_members m JOIN pg_roles b "
                     f"ON b.oid = m.roleid JOIN pg_roles r ON r.oid = m.member WHERE r.rolname='{READER}'")
    assert roles.strip() == "trust_api_reader", roles
    # Isolation: the reader holds no grant on U and its pages read nothing of U.
    seen = psql(db, SELECT.format(ca=U, iss=ISS, sub=SUB, t="NULL", i="NULL").replace(
        "SELECT ca_id,serial_hex", "SELECT count(*) FROM (SELECT ca_id,serial_hex") + ") q",
        user=READER)
    assert seen.strip() == "0", f"reader sees authority U: {seen}"


def cursor(db, filt, position):
    if position == "first":
        return "NULL", "NULL"
    where = f"ca_id='{A}'" + FILTERS[filt]
    count = int(psql(db, f"SELECT count(*) FROM management_certificate WHERE {where}"))
    offset = count // 2 if position == "middle" else max(count - 50, 0)
    row = psql(db, f"SELECT signed_at || '|' || request_id FROM management_certificate WHERE {where} "
                   f"ORDER BY signed_at DESC, request_id DESC OFFSET {offset} LIMIT 1").strip()
    t, i = row.split("|")
    return f"'{t}'", f"'{i}'"


def query(db, filt, position):
    t, i = cursor(db, filt, position)
    return SELECT.format(ca=A, iss=ISS, sub=SUB, t=t, i=i) + FILTERS[filt] + ORDER


def restart_cold():
    subprocess.run(["su", "postgres", "-c",
                    f"/usr/lib/postgresql/16/bin/pg_ctl -D {DATA} -m fast -w restart -l {DATA}/../pg.log"],
                   check=True, capture_output=True)
    subprocess.run(["sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"], check=True)


def explain(db, sql):
    return psql(db, "EXPLAIN (ANALYZE, BUFFERS) " + sql, user=READER)


def exec_ms(plan):
    for line in plan.splitlines():
        if line.startswith("Execution Time:"):
            return float(line.split()[2])
    raise ValueError(plan)


def shared(plan):
    hit = read = 0
    for line in plan.splitlines():
        line = line.strip()
        if line.startswith("Buffers: shared"):
            for part in line.replace("Buffers: shared", "").replace(",", " ").split():
                if part.startswith("hit="):
                    hit = int(part[4:])
                elif part.startswith("read="):
                    read = int(part[5:])
            break
    return hit, read


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cold", action="store_true")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ensure_reader(args.db)
    queries = {name: query(args.db, filt, pos) for name, filt, pos in CASES}
    (out / f"{args.db}-queries.json").write_text(json.dumps(queries, indent=1))
    results = {}
    psql(args.db, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
    for name, sql in queries.items():
        rows = int(psql(args.db, f"SELECT count(*) FROM ({sql}) q", user=READER))
        plan = explain(args.db, sql)
        (out / f"{args.db}-{name}.plan.txt").write_text(plan)
        psql(args.db, "SELECT pg_stat_statements_reset()")
        for _ in range(5):
            psql(args.db, sql, user=READER)
        stat = psql(args.db, f"""SELECT calls, round(mean_exec_time::numeric,2), round(min_exec_time::numeric,2),
               round(max_exec_time::numeric,2), shared_blks_hit / calls, shared_blks_read / calls
               FROM pg_stat_statements s JOIN pg_roles r ON r.oid = s.userid
               WHERE r.rolname = '{READER}' AND s.query LIKE 'SELECT ca_id,serial_hex%'""").strip()
        calls, mean, mn, mx, hit, read = stat.split("|")
        results[name] = {"rows": rows, "calls": int(calls), "mean_ms": float(mean), "min_ms": float(mn),
                         "max_ms": float(mx), "hit": int(hit), "read": int(read)}
        print(name, results[name], flush=True)
    if args.cold:
        for name, sql in queries.items():
            restart_cold()
            time.sleep(1)
            plan = explain(args.db, sql)
            (out / f"{args.db}-{name}.cold.plan.txt").write_text(plan)
            hit, read = shared(plan)
            results[name].update({"cold_ms": exec_ms(plan), "cold_hit": hit, "cold_read": read})
            print(name, "cold", results[name]["cold_ms"], read, flush=True)
    (out / f"{args.db}-results.json").write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
