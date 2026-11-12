#!/usr/bin/env python3
"""Replay tests/fixtures/probes.jsonl through two builds. Fails if any
verdict is below its floor, or weaker than the base build's verdict.

Each line of the corpus is {"cmd", "min", "note"}. `min` is the weakest
verdict the command may get, ordered deny > unsafe > unknown. The CLI never
prints `safe`, so a `safe` verdict is a failure too.

The corpus holds only gaps that are already fixed. A probe for an open gap
would publish the bypass, so those live in a private repo and move here
with their fix.

USAGE

    python3 scripts/probe_replay.py --head . --base <checkout of previous tag>

`--base` is optional; without it, only the floors are checked. A deliberate
loosening against the base fails unless `--allow-loosening` is passed. The
loosened commands are printed either way, so they can be listed in the PR
description.

The deny probes expect the cwd to be a git repo on its default branch
(master) with an origin, so that the git policy has a push to refuse. The
script builds one in a temporary directory.
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile

RANK = {"unknown": 1, "unsafe": 2, "deny": 3}


def short(cmd, width=160):
    """Some probes are tens of KB of stress input."""
    cmd = cmd.replace("\n", "\\n")
    return cmd if len(cmd) <= width else "{}... [{} chars]".format(cmd[:width], len(cmd))


def scratch_repo(root):
    origin = os.path.join(root, "origin.git")
    repo = os.path.join(root, "repo")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    subprocess.run(["git", "init", "-q", "-b", "master", repo], check=True)
    subprocess.run(["git", "-C", repo, "-c", "user.name=probe",
                    "-c", "user.email=probe@example.invalid",
                    "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    subprocess.run(["git", "-C", repo, "remote", "add", "origin", origin],
                   check=True)
    subprocess.run(["git", "-C", repo, "push", "-q", "origin", "master"],
                   check=True)
    return repo


def verdict(build, repo, cmd):
    cli = os.path.join(build, "hooks", "grammar_classifier.py")
    try:
        p = subprocess.run(
            [sys.executable, cli, "--no-user-allow", "--cwd", repo, cmd],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "timeout"
    try:
        return json.loads(p.stdout)["decision"]
    except (ValueError, KeyError):
        return "error"


def run(build, repo, cmds):
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(cmds, pool.map(lambda c: verdict(build, repo, c), cmds)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", required=True)
    ap.add_argument("--base")
    ap.add_argument("--corpus", default="tests/fixtures/probes.jsonl")
    ap.add_argument("--allow-loosening", action="store_true")
    args = ap.parse_args()

    with open(args.corpus) as f:
        probes = [json.loads(line) for line in f if line.strip()]
    cmds = [p["cmd"] for p in probes]
    with tempfile.TemporaryDirectory() as tmp:
        repo = scratch_repo(tmp)
        head = run(args.head, repo, cmds)
        base = run(args.base, repo, cmds) if args.base else {}

    below, looser = [], []
    for p in probes:
        got = head[p["cmd"]]
        if RANK.get(got, 0) < RANK[p["min"]]:
            below.append((p, got))
        prev = base.get(p["cmd"])
        if prev in RANK and RANK.get(got, 0) < RANK[prev]:
            looser.append((p, prev, got))

    for p, got in below:
        print("BELOW FLOOR  {} (min {}): {}".format(got, p["min"], short(p["cmd"])))
    for p, prev, got in looser:
        print("LOOSER  {} -> {}: {}".format(prev, got, short(p["cmd"])))
    print("{} probes; {} below floor; {} looser than base".format(
        len(probes), len(below), len(looser)))
    if below or (looser and not args.allow_loosening):
        sys.exit(1)


if __name__ == "__main__":
    main()
