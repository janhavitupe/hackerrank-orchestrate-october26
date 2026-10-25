"""Request-intent classification: does ``request_text`` authorise deletion?

Two layers:
  * a deterministic multilingual rule classifier (always runs; also the
    fallback when no API key is configured), and
  * an optional LLM pass (Anthropic Messages API) used only for texts the
    rules mark as uncertain, batched to keep token usage low.  Results are
    cached on disk so re-runs cost nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field

PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "intent_classifier.md")
CACHE_PATH = os.path.join(os.path.dirname(__file__), ".cache", "intent_cache.json")
MODEL = os.environ.get("INTENT_MODEL", "claude-opus-5-5")
# USD per million tokens (input, output) for the usage report
PRICES = {"claude-opus-5-5": (4.00, 20.00), "claude-sonnet-5-5": (2.00, 10.00), "claude-haiku-5-5": (0.10, 0.50)}

DELETE_PATTERNS = [
    r"\bdelet", r"\berase", r"\berasure\b", r"\bremove my (account|profile)\b", r"\bclose (my|this) account",
    r"\bclose the account completely", r"\bdeleting my account", r"\bpermanent(ly)? .*delet",
    r"\bremove (my|the) (account|profile)", r"\bremove .* personal (information|data|details)",
    r"supprim", r"suppression", r"eliminaci", r"eliminar", r"exclus[ãa]o", r"excluir", r"삭제", r"削除",
    r"\bclose .*account.* (delet|remov)", r"\bkeep only the reference",
]
FOLLOW_UP_PATTERNS = [
    r"\bremoved?\b", r"\bdeleted\b", r"\bdeletion\b", r"\bgone\b", r"\bclosed my account", r"\bclose .*account",
    r"\bno longer need this account", r"\berased?\b",
]
NEGATIVE_PATTERNS = [
    r"\bdo not (close|delete|remove)", r"\bdon'?t (close|delete|remove)", r"without removing",
    r"\bleave (the|my) (account|profile)", r"\bkeep the account", r"\bcontinue using", r"\bonly\b.*marketing",
    r"marketing lists only", r"\bstop the promotional", r"\bunsubscribe", r"\bsend me a copy",
    r"\bcopy of (the information|last year)", r"\bdownload my", r"\bportable format", r"\bwhat personal information",
    r"\bcorrect (it|my)", r"\bmisspelled", r"\bchange the email", r"\breset(ting)? the login", r"\bout of date",
    r"\binvoices?\b.*records", r"\bleave the account active", r"\bkeep the account as it is",
    # non-English negations / non-deletion asks
    r"\bno (eliminen|borren|cierren)", r"\bsin eliminar", r"\bcopia de (mis|los) datos", r"\bcorregir",
    r"\bne (supprimez|fermez|effacez) pas", r"\bsans supprimer", r"\bcopie de mes donn", r"\bcorriger",
    r"\bnão (exclua|excluam|apague|apaguem|encerre)", r"\bsem excluir", r"\bcópia dos meus dados", r"\bcorrigir",
    r"삭제하지", r"사본", r"수정해", r"削除しない", r"削除せず", r"コピー", r"訂正",
]


@dataclass
class Usage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    by_model: dict = field(default_factory=dict)

    def add(self, model: str, inp: int, out: int) -> None:
        self.calls += 1
        self.input_tokens += inp
        self.output_tokens += out
        m = self.by_model.setdefault(model, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
        m["calls"] += 1
        m["input_tokens"] += inp
        m["output_tokens"] += out


def rule_classify(text: str) -> tuple[bool, float]:
    """Return (authorises_deletion, confidence).

    An explicit non-deletion instruction (correction, access, export, opt-out,
    "do not close the account") wins.  Otherwise any deletion vocabulary -
    including follow-ups about an earlier deletion ("finish the deletion",
    "verify my account was deleted", "remove that search result") - counts as
    a deletion request."""
    t = text.lower()
    neg = any(re.search(p, t) for p in NEGATIVE_PATTERNS)
    pos = any(re.search(p, t) for p in DELETE_PATTERNS + FOLLOW_UP_PATTERNS)
    if neg:
        return False, (0.95 if not pos else 0.7)
    if pos:
        return True, 0.95
    return True, 0.5


def _load_cache() -> dict:
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=1, sort_keys=True)


def _llm_batch(texts: dict[str, str], usage: Usage) -> dict[str, bool]:
    """Classify a batch of texts in a single model call.  Returns {} on any failure."""
    if not texts:
        return {}
    try:
        import anthropic  # type: ignore
    except ImportError:
        return {}
    with open(PROMPT_PATH, encoding="utf-8") as fh:
        system = fh.read()
    items = "\n".join(json.dumps({"id": k, "text": v}, ensure_ascii=False) for k, v in texts.items())
    try:
        # zero-arg client: resolves ANTHROPIC_API_KEY / auth token / ant profile
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=MODEL, max_tokens=4000, system=system,
            output_config={"effort": "low"},
            messages=[{"role": "user", "content": items}],
        )
    except Exception:
        return {}
    if resp.stop_reason == "refusal":
        return {}
    usage.add(MODEL, resp.usage.input_tokens, resp.usage.output_tokens)
    raw = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    out = {}
    for m in re.finditer(r'"id"\s*:\s*"([^"]+)"\s*,\s*"deletion"\s*:\s*(true|false)', raw):
        out[m.group(1)] = m.group(2) == "true"
    return out


def classify_all(requests: list[dict], usage: Usage, use_llm: bool = True) -> dict[str, bool]:
    """case_id -> authorises deletion."""
    cache = _load_cache()
    result: dict[str, bool] = {}
    pending: dict[str, str] = {}
    for r in requests:
        text = r["request_text"]
        h = hashlib.sha256(text.encode()).hexdigest()[:16]
        verdict, conf = rule_classify(text)
        result[r["case_id"]] = verdict
        if h in cache:
            result[r["case_id"]] = cache[h]
        elif use_llm and conf < 0.9:
            pending[h] = text
    if pending:
        hs = list(pending)
        for i in range(0, len(hs), 25):
            chunk = {h: pending[h] for h in hs[i:i + 25]}
            got = _llm_batch(chunk, usage)
            cache.update(got)
        _save_cache(cache)
        for r in requests:
            h = hashlib.sha256(r["request_text"].encode()).hexdigest()[:16]
            if h in cache:
                result[r["case_id"]] = cache[h]
    return result
