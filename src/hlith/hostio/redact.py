# SPDX-License-Identifier: Apache-2.0
"""Best-effort secret hygiene for what an agent run may SHOW a model (E1 agent node).

1. ``sensitive_path``: files an agent may not read at all (env files, private keys, credentials, git metadata, ...).
2. ``redact``: well-known secret SHAPES inside any text replaced by a fixed token, with a COUNT (never the value).

This is pattern matching: a repository secret in an unusual shape can still get through. It reduces accidental exfiltration to a
vendor; it is not a guarantee, which is why a real-model run is restricted to PUBLIC pinned clones (see the E1 contract note)."""

from __future__ import annotations

import fnmatch
import re

TOKEN = "[redacted:secret-shape]"
_DIRS = {".git", ".aws", ".ssh", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".config/gcloud"}
_NAMES = (".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "id_rsa*", "id_dsa*",
          "id_ecdsa*", "id_ed25519*", ".netrc", "_netrc", ".npmrc", ".pypirc", ".htpasswd", "credentials*", "secrets*", "secret.*",
          "*.tfvars", "terraform.tfstate*", ".dockercfg", "*.gpg", "*.asc")


def sensitive_path(rel: str) -> bool:
    """True when the path (any component, or a multi-component directory such as .config/gcloud) names credentials. Meant to be
    applied to the CANONICAL path: the caller must have refused every symlink on the way."""
    parts = [p.lower() for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    joined = "/" + "/".join(parts) + "/"
    if any(p in _DIRS for p in parts) or any(("/" + d + "/") in joined for d in _DIRS if "/" in d):
        return True
    name = parts[-1] if parts else ""
    return any(fnmatch.fnmatch(name, pat) for pat in _NAMES)


def scrub_task(text: str) -> tuple[str, int]:
    """Task text goes into the prompt too: redact secret shapes, and drop tokens that name a sensitive path."""
    out, n = redact(text)
    words = []
    for w in re.split(r"(\s+)", out):
        core = w.strip("\"'`,;:()[]{}")
        if core and not core.isspace() and ("/" in core or "." in core) and sensitive_path(core.lstrip("~")):
            w, n = w.replace(core, "[sensitive-path]"), n + 1
        words.append(w)
    return "".join(words), n


_KEYISH = r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential)"
_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
]
_BEARER = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{6,}")
_KV = re.compile(r"(?i)(\b[A-Za-z0-9_.-]*" + _KEYISH + r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?)([^\s\"'#,;}{]{4,})")


def redact(text: str) -> tuple[str, int]:
    """(text with secret shapes replaced by TOKEN, number of replacements)."""
    n = 0

    def sub(pat, t, repl):
        nonlocal n
        t, k = pat.subn(repl, t)
        n += k
        return t

    for pat in _PATTERNS:
        text = sub(pat, text, TOKEN)
    text = sub(_BEARER, text, lambda m: m.group(1) + TOKEN)
    text = sub(_KV, text, lambda m: m.group(1) + TOKEN)
    return text, n
