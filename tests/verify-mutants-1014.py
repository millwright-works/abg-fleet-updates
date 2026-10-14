"""Verifier mutant runner (rename fleet sec check, 2026-10-14).
Applies each mutation to a COPY of the tool in a folder this script creates, runs the Move suite against the copy
with -ToolScript on Windows PowerShell 5.1, and prints the RESULT line and the FAIL lines. The repo tool is never edited.
Usage: python -I tests/verify-mutants-1014.py <outdir>
"""
import hashlib, os, subprocess, sys

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tool = os.path.join(repo, "src", "BayAgent", "tools", "Move-BayInstall.ps1")
suite = os.path.join(repo, "tests", "BayAgent.MoveInstall.Tests.ps1")
out = sys.argv[1]
os.makedirs(out, exist_ok=False)
orig = open(tool, "rb").read()
h0 = hashlib.sha256(orig).hexdigest()

M = [
    ("V1-newroot-recheck-off", b"if ($toNow.Count -gt 0) {", b"if ($toNow.Count -gt 99) {"),
    ("V2-journal-json-path-read", b'$jText = Read-BmTrustedText (Join-Path $jIn "journal.json")',
     b'$jText = [IO.File]::ReadAllText((Join-Path $jIn "journal.json"))'),
    ("V3-bootstrap-source-unjudged", b"-and [IO.Directory]::Exists($BootstrapSource)) {", b"-and $false) {"),
]
for mid, old, new in M:
    n = orig.count(old)
    if n != 1:
        print(mid, "SKIP replacement count", n)
        continue
    d = os.path.join(out, mid)
    os.makedirs(d)
    p = os.path.join(d, "Move-BayInstall.ps1")
    open(p, "wb").write(orig.replace(old, new))
    log = os.path.join(d, "run.txt")
    with open(log, "wb") as f:
        rc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", suite, "-ToolScript", p],
                            stdout=f, stderr=subprocess.STDOUT, timeout=900).returncode
    text = open(log, "rb").read().decode("utf-8", "replace")
    result = [l for l in text.splitlines() if l.startswith("RESULT:")]
    fails = [l.strip() for l in text.splitlines() if l.strip().startswith("FAIL")]
    print(mid, "exit", rc, result[-1] if result else "NO RESULT LINE")
    for x in fails[:6]:
        print("   ", x[:200])
print("tool unchanged:", hashlib.sha256(open(tool, "rb").read()).hexdigest() == h0)
