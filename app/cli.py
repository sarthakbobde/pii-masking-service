"""Command line: python -m app.cli <command>

  create-key NAME --permissions mask [--rate-limit 120]
  list-keys
  revoke-key ID
"""
import argparse
import json
import sys

from app import auth
from app.config import config
from app.db import init_db


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-key")
    c.add_argument("name")
    c.add_argument("--permissions", required=True, help="comma-separated: " + ",".join(auth.PERMISSIONS))
    c.add_argument("--rate-limit", type=int, default=None)
    sub.add_parser("list-keys")
    r = sub.add_parser("revoke-key")
    r.add_argument("id", type=int)
    args = ap.parse_args(argv)

    db = init_db(config.database_url)
    try:
        if args.cmd == "create-key":
            info, key = auth.create(args.name, [p.strip() for p in args.permissions.split(",") if p.strip()],
                                    args.rate_limit, "cli", db=db)
            print(json.dumps({**info, "key": key}, default=str, indent=2))
            print("Store the key now: it is not shown again.", file=sys.stderr)
        elif args.cmd == "list-keys":
            print(json.dumps(auth.list_keys(db), default=str, indent=2))
        elif args.cmd == "revoke-key":
            print(json.dumps(auth.revoke(args.id, db), default=str, indent=2))
    except (ValueError, LookupError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
