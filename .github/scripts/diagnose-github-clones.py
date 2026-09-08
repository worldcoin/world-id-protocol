"""Bounded probes of Git HTTP auth failures; never print request credentials."""

import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPOS = [
    "foundry-rs/forge-std",
    "OpenZeppelin/openzeppelin-contracts",
    "OpenZeppelin/openzeppelin-contracts-upgradeable",
    "0xOsiris/poseidon-solidity",
    "TaceoLabs/oprf-key-registry",
    "ethereum-optimism/optimism",
]
TOKEN = os.environ.pop("DIAGNOSTIC_TOKEN", "")
BASIC = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
SAFE_HEADER = re.compile(
    r"^(HTTP/|date:|server:|content-type:|www-authenticate:|retry-after:|"
    r"x-ratelimit-|x-github-request-id:|via:|x-cache:)", re.I
)


def redact(value):
    return value.replace(TOKEN, "[REDACTED]").replace(BASIC, "[REDACTED]") if TOKEN else value


def run(args, timeout=45, **kwargs):
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
        return result.returncode, result.stdout, result.stderr, round(time.monotonic() - started, 2)
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout} seconds", timeout


if len(sys.argv) > 1 and sys.argv[1] in ("--build", "--recover"):
    with tempfile.TemporaryDirectory() as tmp:
        trace = Path(tmp) / "git-http.log"
        env = os.environ.copy()
        env.update(GIT_TERMINAL_PROMPT="0", GIT_TRACE_CURL=str(trace), GIT_TRACE_CURL_NO_DATA="1")
        if sys.argv[1] == "--recover":
            assert TOKEN
            env.update(
                GIT_CONFIG_COUNT="1",
                GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {BASIC}",
            )
        code, out, err, duration = run(["make", "sol-build"], env=env, timeout=900)
        for line in (out + "\n" + err).splitlines():
            if not any(x in line for x in ("Receiving objects:", "Resolving deltas:", "Counting objects:", "Compressing objects:")):
                print(redact(line))
        print(f"build exit={code}, seconds={duration}")
        if trace.exists():
            print("::group::Actual clone HTTP responses")
            for line in trace.read_text().splitlines():
                if "<= Recv header:" in line:
                    header = line.split("<= Recv header:", 1)[1].strip()
                    if SAFE_HEADER.match(header):
                        print(redact(line))
                elif re.search(r"=> Send header: (GET|POST) ", line):
                    print(redact(line))
            print("::endgroup::")
        sys.exit(code)


print("UTC:", datetime.datetime.now(datetime.timezone.utc).isoformat(), flush=True)
print(run(["git", "--version"])[1].strip())
print(run(["curl", "--version"])[1].splitlines()[0])
# Report presence only: configuration values may contain credentials.
for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "GIT_CONFIG_COUNT"):
    print(f"{key}: {'set' if key in os.environ else 'unset'}")
for category, pattern in (
    ("URL rewrites", r"^url\..*\.insteadof$"),
    ("credential helpers", r"^credential\..*helper$"),
    ("HTTP overrides", r"^http\."),
):
    code, out, _, _ = run(["git", "config", "--get-regexp", pattern])
    print(f"{category}: {len(out.splitlines()) if code == 0 else 0} entries")

with tempfile.TemporaryDirectory() as tmp:
    for repo in REPOS:
        print(f"::group::{repo}", flush=True)
        # Plain curl tests the same discovery endpoint without Git config or helpers.
        for label, url in (
            ("git-discovery", f"https://github.com/{repo}/info/refs?service=git-upload-pack"),
        ):
            headers, body = Path(tmp) / "headers", Path(tmp) / "body"
            code, out, err, duration = run([
                "curl", "-q", "-sS", "--max-time", "30", "-L",
                "-H", "Git-Protocol: version=2", "-D", str(headers),
                "-o", str(body), "-w", "%{http_code}", url,
            ])
            print(f"{label}: exit={code}, HTTP={out}, seconds={duration}")
            if headers.exists():
                for line in headers.read_text().splitlines():
                    if SAFE_HEADER.match(line):
                        print(redact(line))
            if out != "200" and body.exists():
                print("error body:", redact(body.read_bytes()[:1500].decode(errors="replace")))
            if err:
                print(redact(err))
        for mode in ("anonymous-default-config", "anonymous-clean-config", "authenticated-clean-config"):
            env = os.environ.copy()
            env.update(GIT_TERMINAL_PROMPT="0", GIT_TRACE_CURL="1", GIT_TRACE_CURL_NO_DATA="1")
            if "clean-config" in mode:
                env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_COUNT="0")
                env.pop("GIT_CONFIG_PARAMETERS", None)
            if mode == "authenticated-clean-config":
                env.update(
                    GIT_CONFIG_COUNT="1",
                    GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                    GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {BASIC}",
                )
            code, out, err, duration = run(
                ["git", "ls-remote", f"https://github.com/{repo}", "HEAD"], env=env, cwd=tmp
            )
            print(f"{mode}: exit={code}, seconds={duration}, HEAD={out.strip()}")
            # Only selected inbound headers and Git errors. Never emit outgoing headers.
            for line in err.splitlines():
                if "<= Recv header:" in line:
                    header = line.split("<= Recv header:", 1)[1].strip()
                    if SAFE_HEADER.match(header):
                        print(redact(header))
                elif line.startswith(("fatal:", "error:", "remote:", "Timed out")):
                    print(redact(line))
        print("::endgroup::", flush=True)

    print("::group::REST quota (separate from Git transport)", flush=True)
    code, out, err, duration = run(["curl", "-q", "-sS", "--max-time", "30", "https://api.github.com/rate_limit"])
    print(f"exit={code}, seconds={duration}")
    try:
        data = json.loads(out)
        print(json.dumps(data.get("resources", data), indent=2))
    except ValueError:
        print(redact(out[:1500]))
    print("::endgroup::", flush=True)
