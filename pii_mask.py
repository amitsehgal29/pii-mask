#!/usr/bin/env python3
"""pii-mask: mask PII columns in a CSV before it leaves a secure zone.

Standard library only. Each column gets one strategy:
  hash     keyed HMAC-SHA256 (stable, joinable across files with the same key)
  redact   replace with a fixed token
  partial  keep the last N characters, star the rest
  email    keep the domain, hash the local part
  drop     remove the column
Strategies come from repeated --rule COL=STRATEGY[:ARG] flags.
"""
import argparse
import csv
import hashlib
import hmac
import os
import sys

STRATEGIES = {"hash", "redact", "partial", "email", "drop"}


def h(value, key, length=16):
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:length]


def mask_value(value, strategy, arg, key):
    if value is None or value == "":
        return value
    if strategy == "hash":
        return h(value, key)
    if strategy == "redact":
        return arg or "[REDACTED]"
    if strategy == "partial":
        keep = int(arg or 4)
        if keep <= 0 or len(value) <= keep:
            return "*" * len(value)
        return "*" * (len(value) - keep) + value[-keep:]
    if strategy == "email":
        local, sep, domain = value.rpartition("@")
        if not sep or not local:
            return h(value, key)
        return f"{h(local, key, 10)}@{domain}"
    raise ValueError(f"unknown strategy {strategy!r}")


def parse_rule(text):
    col, eq, spec = text.partition("=")
    if not eq or not col:
        raise ValueError(f"rule must be COL=STRATEGY[:ARG], got {text!r}")
    strategy, _, arg = spec.partition(":")
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}; pick from {sorted(STRATEGIES)}")
    if strategy == "partial" and arg and not arg.isdigit():
        raise ValueError("partial takes a whole number, e.g. partial:4")
    return col, strategy, arg


def mask_rows(rows, fields, rules, key):
    missing = [c for c in rules if c not in fields]
    if missing:
        raise KeyError(f"columns not in input: {missing}")
    out_fields = [f for f in fields if rules.get(f, ("",))[0] != "drop"]
    out = []
    for row in rows:
        new = {}
        for f in out_fields:
            if f in rules:
                s, a = rules[f]
                new[f] = mask_value(row.get(f), s, a, key)
            else:
                new[f] = row.get(f)
        out.append(new)
    return out_fields, out


def main(argv=None):
    p = argparse.ArgumentParser(description="Mask PII columns in a CSV.")
    p.add_argument("source")
    p.add_argument("--rule", action="append", default=[], help="COL=STRATEGY[:ARG], repeatable")
    p.add_argument("--key-env", default="PII_MASK_KEY", help="env var holding the HMAC key (default PII_MASK_KEY)")
    p.add_argument("-o", "--output", default="-")
    args = p.parse_args(argv)

    if not args.rule:
        print("pii-mask: give at least one --rule", file=sys.stderr)
        return 2
    try:
        rules = {}
        for r in args.rule:
            c, s, a = parse_rule(r)
            rules[c] = (s, a)
    except ValueError as e:
        print(f"pii-mask: {e}", file=sys.stderr)
        return 2
    needs_key = any(s in ("hash", "email") for s, _ in rules.values())
    key = os.environ.get(args.key_env, "")
    if needs_key and not key:
        print(f"pii-mask: set {args.key_env} so hashes can't be reversed by guessing", file=sys.stderr)
        return 2

    with open(args.source, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        rows = list(reader)
    try:
        out_fields, out_rows = mask_rows(rows, fields, rules, key.encode("utf-8"))
    except KeyError as e:
        print(f"pii-mask: {e.args[0]}", file=sys.stderr)
        return 2

    out = sys.stdout if args.output == "-" else open(args.output, "w", newline="", encoding="utf-8")
    try:
        w = csv.DictWriter(out, fieldnames=out_fields)
        w.writeheader()
        w.writerows(out_rows)
    finally:
        if out is not sys.stdout:
            out.close()
    print(f"pii-mask: masked {len(out_rows)} rows, {len(rules)} rules", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
