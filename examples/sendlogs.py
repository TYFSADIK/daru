#!/usr/bin/env python3
"""Send sample logs to Daru using the HEC-compatible endpoint.

Usage:
  python3 sendlogs.py --server http://localhost:8088 --token YOUR_TOKEN --count 500
"""

import argparse
import json
import random
import time
import urllib.request

HOSTS = ["web01", "web02", "web03", "api01", "api02", "db01"]
PATHS = ["/", "/login", "/api/users", "/api/orders", "/health", "/static/app.js"]
STATUSES = [200, 200, 200, 200, 301, 404, 500, 503]
USERS = ["alice", "bob", "carol", "dave", "eve"]
METHODS = ["GET", "GET", "GET", "POST", "PUT", "DELETE"]


def make_event(now):
    host = random.choice(HOSTS)
    if host.startswith("api"):
        obj = {
            "user": random.choice(USERS),
            "action": random.choice(["create", "read", "update", "delete"]),
            "status": random.choice(STATUSES),
            "latency_ms": random.randint(2, 900),
        }
        return {"time": now, "host": host, "sourcetype": "api_json", "event": obj}
    status = random.choice(STATUSES)
    bytes_sent = random.randint(120, 24000)
    ip = f"10.0.{random.randint(0,4)}.{random.randint(1,254)}"
    line = f'{ip} - - "{random.choice(METHODS)} {random.choice(PATHS)} HTTP/1.1" {status} {bytes_sent}'
    return {"time": now, "host": host, "sourcetype": "access_combined", "event": line}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://localhost:8088")
    ap.add_argument("--token", required=True)
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--spread-hours", type=float, default=24.0,
                    help="spread events across this many past hours")
    args = ap.parse_args()

    now = time.time()
    batch = []
    for i in range(args.count):
        ts = now - random.random() * args.spread_hours * 3600
        batch.append(json.dumps(make_event(round(ts, 3))))
    body = "\n".join(batch).encode()

    req = urllib.request.Request(
        args.server.rstrip("/") + "/services/collector",
        data=body,
        headers={"Authorization": "Splunk " + args.token, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(resp.read().decode())
    print(f"sent {args.count} events")


if __name__ == "__main__":
    main()
