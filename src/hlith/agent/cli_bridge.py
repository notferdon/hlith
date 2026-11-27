# SPDX-License-Identifier: Apache-2.0
"""E1 hosted-agent bridge: one proposer turn through a coding-agent CLI the HOST has already authenticated.

Standalone (stdlib only, no hlith imports): the engine runs it host-side as
``<python> -I cli_bridge.py <config.json>`` through CommandProposer, ONLY via ``--hosted-agent-config``, after the engine has
checked the public scope (engine_cli._hosted_agent_proposer). It never sees the repository: its input is the proposer turn
JSON on stdin ({"turn", "task", "transcript"}: transcript = tool results from the run's stage), its output is
{"tool_calls": [...]} on stdout, which the CONFINED worker executes against the stage. Hlith reads no credential; the CLI uses
its own login under the configured HOME.

Config (operator-owned JSON file outside the repository; no defaults, so nothing is sent without one):
  provider          a RECOGNISED profile; the bridge builds the argv itself, an arbitrary provider argv is not accepted:
                      "claude-cli": <executable> -p --tools "" --strict-mcp-config --restricted --safe-mode
                                    --disable-slash-commands --no-session-persistence --output-format text [--model M]
                                    (the CLI's own documented controls: no built-in tools, no MCP servers, no settings
                                    files, no customizations, no saved session)
                      "local-stand-in": <executable> with no arguments; a local program for plumbing traces only; never
                                    a model and never E1 evidence
                    Not supported: codex (its read-only sandbox still exposes read tools); add a profile only with a
                    documented tools-off control.
  executable        absolute path of the provider CLI binary (its sha256 is recorded per turn)
  model             optional model name (claude-cli only)
  home, path        HOME and PATH for the provider (its own login lives there)
  public_scope      {"origin_url": "https://...", "commit": "<40 hex>", "attested_public": true}: the ENGINE checks the
                    origin and that every repository the worker can read is exactly that commit with no uncommitted,
                    untracked or ignored files; that the origin is PUBLIC is the operator's attestation (not network-verified)
  max_turns         turn ceiling (1..50): at the ceiling the bridge finishes without calling the provider
  deadline_s        wall seconds per provider call (1..900)
  max_prompt_bytes  transcript is cut to fit (1024..2000000)
  max_reply_bytes   provider stdout cap (1024..4000000)
  redact            optional list of regexes removed from the task text before it is sent
  audit_dir         optional absolute directory: one JSON line per turn (hashes, rc, seconds; never the text)

Exit status: 0 with JSON on stdout; 2 config error; 3 provider failed, timed out, exceeded a cap or replied without a valid
tool-call object (the engine then refuses the run; nothing is guessed)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

TOOLS = {"read_file": {"path"}, "apply_patch": {"diff"}, "declare": {"paths"}, "finish": set()}
PROTOCOL = (
    "You propose a change to a public repository through tool calls only. You cannot run commands. Reply with ONE JSON object "
    "and nothing else: {\"tool_calls\": [...]}. Calls: {\"name\": \"read_file\", \"path\": REL} reads a file (the result comes "
    "back next turn); {\"name\": \"apply_patch\", \"diff\": UNIFIED_DIFF} applies a git diff; {\"name\": \"declare\", "
    "\"paths\": {REL: \"modified\"|\"added\"|\"deleted\"}, \"deltas\": [...]} declares what you changed; {\"name\": \"finish\", "
    "\"summary\": TEXT} ends the run. Hlith verifies the change independently; your declaration is a claim, not proof.")
PROFILES = {
    "claude-cli": lambda exe, model: [exe, "-p", "--tools", "", "--strict-mcp-config", "--restricted", "--safe-mode",
                                      "--disable-slash-commands", "--no-session-persistence", "--output-format", "text",
                                      *(["--model", model] if model else [])],
    "local-stand-in": lambda exe, model: [exe],
}
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_ABS_PATH = re.compile(r"(?<![\w.])/(?:home|root|tmp|var|Users)/[^\s'\"]+")


class ConfigError(ValueError):
    pass


def _int(cfg: dict, key: str, lo: int, hi: int) -> int:
    v = cfg.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ConfigError(f"{key} must be an integer in [{lo}, {hi}]")
    return v


def load_config(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            cfg = json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read config ({type(e).__name__})") from None
    if not isinstance(cfg, dict):
        raise ConfigError("config must be a JSON object")
    if "provider_argv" in cfg:
        raise ConfigError("provider_argv is not accepted: name a recognised provider profile")
    provider = cfg.get("provider")
    if provider not in PROFILES:
        raise ConfigError(f"provider must be one of {sorted(PROFILES)}")
    exe = cfg.get("executable")
    if not (isinstance(exe, str) and os.path.isabs(exe) and os.path.isfile(exe) and os.access(exe, os.X_OK)):
        raise ConfigError("executable must be an absolute path to an executable file")
    model = cfg.get("model")
    if model is not None and (provider != "claude-cli" or not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", model)):
        raise ConfigError("model is a short name and only for claude-cli")
    argv = PROFILES[provider](exe, model)
    for key in ("home", "path"):
        if not isinstance(cfg.get(key), str) or not cfg[key]:
            raise ConfigError(f"{key} must be a non-empty string")
    if not os.path.isabs(cfg["home"]):
        raise ConfigError("home must be absolute")
    scope = cfg.get("public_scope")
    if not (isinstance(scope, dict) and isinstance(scope.get("origin_url"), str) and scope["origin_url"].startswith("https://")
            and isinstance(scope.get("commit"), str) and _HEX40.match(scope["commit"]) and scope.get("attested_public") is True):
        raise ConfigError("public_scope must be {origin_url: https://..., commit: 40 lowercase hex, attested_public: true}")
    out = {"provider": provider, "executable": exe, "provider_argv": argv, "home": cfg["home"], "path": cfg["path"], "public_scope": dict(scope),
           "max_turns": _int(cfg, "max_turns", 1, 50), "deadline_s": _int(cfg, "deadline_s", 1, 900),
           "max_prompt_bytes": _int(cfg, "max_prompt_bytes", 1024, 2_000_000),
           "max_reply_bytes": _int(cfg, "max_reply_bytes", 1024, 4_000_000)}
    redact = cfg.get("redact", [])
    if not (isinstance(redact, list) and all(isinstance(r, str) for r in redact)):
        raise ConfigError("redact must be a list of regex strings")
    try:
        out["redact"] = [re.compile(r) for r in redact]
    except re.error:
        raise ConfigError("redact contains an invalid regex") from None
    audit = cfg.get("audit_dir")
    if audit is not None and not (isinstance(audit, str) and os.path.isabs(audit)):
        raise ConfigError("audit_dir must be an absolute path")
    out["audit_dir"] = audit
    return out


def redact_task(task: str, patterns: list) -> str:
    for p in patterns:
        task = p.sub("[redacted]", task)
    return _ABS_PATH.sub("[path]", task)


def build_prompt(turn: dict, cfg: dict) -> bytes:
    head = f"{PROTOCOL}\nTASK: {redact_task(str(turn.get('task', '')), cfg['redact'])}\nTURN: {int(turn.get('turn', 0))}\nTRANSCRIPT: "
    budget = cfg["max_prompt_bytes"] - len(head.encode("utf-8"))
    tr = json.dumps(turn.get("transcript", []), ensure_ascii=False)
    tr_b = tr.encode("utf-8")
    if len(tr_b) > budget:  # keep the most recent tool results: they are what the next call depends on
        tr_b = b"[earlier transcript cut]..." + tr_b[-max(0, budget - 32):]
    return head.encode("utf-8") + tr_b


def extract_tool_calls(text: str) -> dict | None:
    """The first JSON object in the reply that has a valid ``tool_calls`` list (fenced or bare); None if there is none."""
    dec = json.JSONDecoder()
    i = text.find("{")
    while i != -1:
        try:
            obj, _end = dec.raw_decode(text, i)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("tool_calls"), list) and _valid_calls(obj["tool_calls"]):
            return {"tool_calls": obj["tool_calls"]}
        i = text.find("{", i + 1)
    return None


def _valid_calls(calls: list) -> bool:
    if not calls:
        return False
    for c in calls:
        if not isinstance(c, dict) or c.get("name") not in TOOLS or not TOOLS[c["name"]] <= set(c):
            return False
        if c["name"] == "read_file" and not isinstance(c["path"], str):
            return False
        if c["name"] == "apply_patch" and not isinstance(c["diff"], str):
            return False
        if c["name"] == "declare" and not isinstance(c["paths"], dict):
            return False
    return True


def _file_sha256(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _audit(cfg: dict, rec: dict) -> None:
    if not cfg.get("audit_dir"):
        return
    try:
        os.makedirs(cfg["audit_dir"], exist_ok=True)
        with open(os.path.join(cfg["audit_dir"], "bridge-audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    except OSError:
        pass


def run_turn(turn: dict, cfg: dict) -> tuple[int, dict | None]:
    t = int(turn.get("turn", 0))
    if t >= cfg["max_turns"]:
        out = {"tool_calls": [{"name": "finish", "summary": f"turn ceiling {cfg['max_turns']} reached"}]}
        _audit(cfg, {"turn": t, "result": "ceiling"})
        return 0, out
    prompt = build_prompt(turn, cfg)
    env = {"HOME": cfg["home"], "PATH": cfg["path"], "LANG": "C.UTF-8"}
    start = time.monotonic()
    rec = {"turn": t, "prompt_sha256": hashlib.sha256(prompt).hexdigest(), "prompt_bytes": len(prompt),
           "provider": cfg["provider"], "provider_argv_sha256": hashlib.sha256(json.dumps(cfg["provider_argv"]).encode()).hexdigest(),
           "executable_sha256": _file_sha256(cfg["executable"])}
    with tempfile.TemporaryDirectory(prefix="hlith-e1-") as cwd:  # empty cwd: the provider gets no files from us but the prompt
        try:
            proc = subprocess.run(cfg["provider_argv"], input=prompt, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=env, cwd=cwd, timeout=cfg["deadline_s"])
        except subprocess.TimeoutExpired:
            _audit(cfg, {**rec, "result": "timeout", "seconds": round(time.monotonic() - start, 3)})
            return 3, None
        except OSError as e:
            _audit(cfg, {**rec, "result": f"oserror:{type(e).__name__}"})
            return 3, None
    rec.update(rc=proc.returncode, seconds=round(time.monotonic() - start, 3), reply_bytes=len(proc.stdout),
               reply_sha256=hashlib.sha256(proc.stdout).hexdigest())
    if proc.returncode != 0 or len(proc.stdout) > cfg["max_reply_bytes"]:
        _audit(cfg, {**rec, "result": "provider-failed" if proc.returncode else "reply-cap"})
        return 3, None
    out = extract_tool_calls(proc.stdout.decode("utf-8", "replace"))
    _audit(cfg, {**rec, "result": "ok" if out else "no-valid-tool-calls"})
    return (0, out) if out else (3, None)


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: cli_bridge.py CONFIG.json [CONFIG_SHA256]  (turn JSON on stdin)", file=sys.stderr)
        return 2
    if len(argv) == 3:  # the engine binds the config's content into the argv (and so into the saved thread): verify it here
        try:
            with open(argv[1], "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            actual = None
        if actual != argv[2]:
            print("hlith e1 bridge: config changed since the engine read it", file=sys.stderr)
            return 2
    try:
        cfg = load_config(argv[1])
    except ConfigError as e:
        print(f"hlith e1 bridge: config: {e}", file=sys.stderr)
        return 2
    try:
        turn = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 3
    if not isinstance(turn, dict):
        return 3
    rc, out = run_turn(turn, cfg)
    if out is not None:
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
        sys.stdout.flush()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
