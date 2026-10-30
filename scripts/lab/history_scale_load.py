#!/usr/bin/env python3
"""Lab-only concurrent load for the history filter scale study. Disposable data.

Builds one fixed pgbench script from the study's queries (grant check, then
one history page chosen by pgbench's seeded random() among six cases) and
runs it as the reader login with 1, 10 and 50 clients, logging every
transaction. Reports p50/p95/p99/max latency, throughput and how many
transactions exceeded the API's 3 s statement timeout. The timeout itself is
not set: a pgbench client that gets a cancellation aborts, which would lower
the concurrency being measured.
Usage: python3 -I scripts/lab/history_scale_load.py --db scale_1m --dir OUT [--seconds 60]
"""
import argparse
import glob
import json
import os
import pathlib
import statistics
import subprocess

CASES = ["page1", "middle", "CN-medium", "SAN-strong", "NA-medium", "ALL-medium"]
GRANT = ("SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer='https://issuer.scale.invalid' "
         "AND subject='reader' AND ca_id='dddddddd-0000-4000-8000-0000000000a1');")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args()
    out = pathlib.Path(args.dir)
    queries = json.loads((out / f"{args.db}-queries.json").read_text())
    lines = [f"\\set r random(1, {len(CASES)})"]
    for i, case in enumerate(CASES, 1):
        lines.append(("\\if" if i == 1 else "\\elif") + f" :r = {i}")
        lines.append(GRANT)
        lines.append(queries[case] + ";")
    lines.append("\\endif")
    script = out / f"{args.db}-load.pgb"
    script.write_text("\n".join(lines) + "\n")
    url = f"postgresql://scale_reader:test-only-not-secret@127.0.0.1:55442/{args.db}"
    report = {}
    for clients in (1, 10, 50):
        prefix = out / f"{args.db}-c{clients}"
        for old in glob.glob(f"{prefix}*.log*"):
            os.remove(old)
        res = subprocess.run(
            ["pgbench", "-n", "-c", str(clients), "-j", str(min(clients, 4)), "-T", str(args.seconds),
             "--random-seed=42", "-l", f"--log-prefix={prefix}", "-f", str(script), url],
            capture_output=True, text=True, cwd=out)
        lat = []
        for log in glob.glob(f"{prefix}*"):
            if log.endswith(".pgb"):
                continue
            for row in open(log):
                parts = row.split()
                if len(parts) > 2 and parts[2].isdigit():
                    lat.append(int(parts[2]) / 1000.0)
        lat.sort()
        q = statistics.quantiles(lat, n=100) if len(lat) > 1 else [lat[0]] * 99
        tps = next((l.split("=")[1].split()[0] for l in res.stdout.splitlines() if l.startswith("tps")), "?")
        failed = next((l for l in res.stdout.splitlines() if "failed" in l), "")
        report[clients] = {"tx": len(lat), "tps": tps, "p50_ms": round(q[49], 1), "p95_ms": round(q[94], 1),
                           "p99_ms": round(q[98], 1), "max_ms": round(lat[-1], 1),
                           "over_3s": sum(1 for x in lat if x > 3000), "pgbench": failed.strip(),
                           "stderr": res.stderr.strip()[-300:]}
        print(args.db, clients, report[clients], flush=True)
    (out / f"{args.db}-load.json").write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
