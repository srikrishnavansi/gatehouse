"""The deterministic half of gatehouse: which tools a profile sees, what a call is allowed to do,
what the model is allowed to read back. Plain functions over plain data, so every decision is
the same on every run and can be unit-tested without an MCP server in sight."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ACTIONS = ("allow", "deny", "handoff")


@dataclass(frozen=True)
class Decision:
    action: str                      # allow | deny | handoff
    rule: str | None = None
    reason: str = ""

    def as_error(self) -> dict:
        """Errors as data, the way the InteractiveAI docs ask tools to return them."""
        out = {"error": "needs_human" if self.action == "handoff" else "not_allowed",
               "rule": self.rule, "reason": self.reason}
        if self.action == "handoff":
            out["next"] = "Call built-in:initiate_human_handoff with this reason as the internal_note."
        return out


@dataclass
class Rule:
    id: str
    tools: list[str]
    action: str
    reason: str = ""
    when: dict = field(default_factory=dict)

    def matches(self, tool: str, args: dict) -> bool:
        return tool in self.tools and all(_test(args.get(k), test) for k, test in self.when.items())


# Read arguments the way the upstream's validator will (pydantic lax mode), so a rule never
# decides on "true" while the tool executes on True. Anything unreadable raises: fail closed.
_TRUE, _FALSE = {"true", "1", "yes", "on", "t", "y"}, {"false", "0", "no", "off", "f", "n"}


def _num(value) -> float:
    if isinstance(value, bool):
        raise TypeError("a boolean is not an amount")
    n = float(value)
    if not math.isfinite(n):                       # NaN > 50 is False: never let that read as "allowed"
        raise ValueError("non-finite number")
    return n


def _same(value, want) -> bool:
    if isinstance(want, bool) and isinstance(value, str):
        v = value.strip().lower()
        value = True if v in _TRUE else False if v in _FALSE else value
    elif isinstance(want, (int, float)) and not isinstance(want, bool) and isinstance(value, str):
        value = _num(value)
    return value == want


def _test(value, test: dict) -> bool:
    for op, want in test.items():
        if op == "missing":
            ok = (value is None or (isinstance(value, str) and not value.strip())) == want
        elif value is None:
            ok = False
        elif op == "gt":
            ok = _num(value) > want
        elif op == "gte":
            ok = _num(value) >= want
        elif op == "lt":
            ok = _num(value) < want
        elif op == "lte":
            ok = _num(value) <= want
        elif op == "equals":
            ok = _same(value, want)
        elif op == "in":
            ok = any(_same(value, w) for w in want)
        elif op == "matches":
            ok = re.search(want, value if isinstance(value, str) else json.dumps(value)) is not None
        else:
            raise ValueError(f"unknown condition {op!r}")
        if not ok:
            return False
    return True


# ---- masking ---------------------------------------------------------------------------------

def _last4(v) -> str:
    s = re.sub(r"\s", "", str(v))
    return "****" + s[-4:]


def _domain(v) -> str:
    s = str(v)
    return "***@" + s.split("@", 1)[1] if "@" in s else "***"


FIELD_MASKS = {"last4": _last4, "domain": _domain, "redact": lambda v: "[redacted]"}

# Free-text scrubbing for PII the upstream puts inside sentences rather than named fields.
PATTERNS = {
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"\+\d[\d\s-]{7,}\d"),          # international format only: "+34 600..."
    "card": re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
}


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def scrub(text: str, patterns: list[str]) -> str:
    for name in patterns:
        if name == "card":
            text = PATTERNS["card"].sub(
                lambda m: _last4(m[0]) if _luhn(re.sub(r"\D", "", m[0])) else m[0], text)
        elif name == "email":
            text = PATTERNS["email"].sub(lambda m: _domain(m[0]), text)
        else:
            text = PATTERNS[name].sub(lambda m: _last4(m[0]), text)
    return text


def _key(name) -> str:
    """iban, IBAN, Iban and date_of_birth / dateOfBirth / date-of-birth all name the same field."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


@dataclass
class Masker:
    fields: dict[str, str] = field(default_factory=dict)   # field name -> last4 | domain | redact | drop
    patterns: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.fields = {_key(k): v for k, v in self.fields.items()}

    def __call__(self, obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                how = self.fields.get(_key(k))
                if how == "drop":
                    continue
                out[k] = FIELD_MASKS[how](v) if how and v is not None else self(v)
            return out
        if isinstance(obj, list):
            return [self(v) for v in obj]
        if isinstance(obj, str):
            return scrub(obj, self.patterns)
        return obj

    def text(self, s: str) -> str:
        """Mask a text block: JSON is masked field by field, anything else is scrubbed."""
        try:
            return json.dumps(self(json.loads(s)), ensure_ascii=False)
        except (ValueError, TypeError):
            return scrub(s, self.patterns)


# ---- idempotency -----------------------------------------------------------------------------

class Replays:
    """Same write with the same arguments inside the window returns the first result instead of
    running twice. Keyed on tool + arguments, not session: MCP session ids are not stable across
    transports, and the same bonus to the same player twice in ten minutes is a retry either way.
    ponytail: in-process dict, so one replica; move it to Redis for several."""

    def __init__(self, tools: list[str], window_seconds: int):
        self.tools, self.window, self.seen = set(tools), window_seconds, {}

    def key(self, tool: str, args: dict) -> str | None:
        if tool not in self.tools:
            return None
        blob = json.dumps([tool, args], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, key):
        hit = self.seen.get(key)
        return hit[1] if hit and time.monotonic() - hit[0] < self.window else None

    def put(self, key, result):
        self.seen[key] = (time.monotonic(), result)


# ---- the gate --------------------------------------------------------------------------------

@dataclass
class Gate:
    profiles: dict[str, list[str]]
    rules: list[Rule]
    mask: Masker
    replays: Replays
    upstream: str = ""
    api_key: str | None = None
    api_key_declared: bool = False      # config asked for a key; if it resolves empty, refuse to serve
    audit_log: str | None = None

    def visible(self, profile: str, tool: str) -> bool:
        return tool in self.profiles[profile]

    def decide(self, profile: str, tool: str, args: dict) -> Decision:
        if not self.visible(profile, tool):
            return Decision("deny", "profile", f"{tool} is not in the {profile} profile.")
        for rule in self.rules:                          # first match wins, like a firewall
            try:
                hit = rule.matches(tool, args)
            except (TypeError, ValueError):              # e.g. amount_eur="lots": fail closed
                return Decision("deny", rule.id, f"Could not evaluate {rule.id} on these arguments.")
            if hit:
                return Decision(rule.action, rule.id, rule.reason)
        return Decision("allow")


def _env(value):
    """${VAR} references, the manifest convention, resolved from the environment."""
    if isinstance(value, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m[1], ""), value) or None
    return value


def load(path: str | Path) -> Gate:
    path = Path(path)
    cfg = yaml.safe_load(path.read_text())
    rules = [Rule(**r) for r in cfg.get("rules", [])]
    for r in rules:
        if r.action not in ACTIONS:
            raise ValueError(f"rule {r.id}: action must be one of {ACTIONS}")
    upstream = _env(cfg["upstream"])                            # ${OPERATOR_MCP_URL} works too
    if not upstream.startswith(("http://", "https://")):
        upstream = str((path.parent / upstream).resolve())      # a local server file, relative to the config
    idem = cfg.get("idempotency", {})
    m = cfg.get("mask", {})
    return Gate(
        profiles={name: p["tools"] for name, p in cfg["profiles"].items()},
        rules=rules,
        mask=Masker(m.get("fields", {}), m.get("patterns", [])),
        replays=Replays(idem.get("tools", []), idem.get("window_seconds", 600)),
        upstream=upstream,
        api_key=_env(cfg.get("api_key")),
        api_key_declared=bool(cfg.get("api_key")),
        audit_log=str(path.parent / cfg["audit_log"]) if cfg.get("audit_log") else None,
    )
