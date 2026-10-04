"""Policy compiler, deterministic half.

  * compile_fixture(): the rule parser. It READS the text you give it (regex / keyword rules per sentence);
    it is not a canned answer. It is the labelled, model-free fallback and the default for CI.
  * finalize(): shared by the fixture AND the LLM path. Assigns C1..Cn, validates every clause with the
    pydantic models, guarantees the scope / window ambiguity questions are always asked, and stores the
    internal param patches server-side. Patches are NEVER part of the public PolicyDraft shape.
  * apply_answers(): turns the developer's answers into final clauses at approval time.

Supported: per_txn_limit, cumulative_limit, data_scope, precondition (only these four kinds, three tools).
Anything else is a stated limitation and produces COMPILE_FAILED, not a guess.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from models import KIND_ACTION, Ambiguity, AmbiguityOption, Clause

ALLOWED_PATCH_KEYS = {"scope", "window_type", "environments", "mode"}  # each still has to validate for its kind
SUPPORTED_TEXT = (
    "Supported rules: a per-refund amount limit that needs human approval, a cumulative refund limit per customer "
    "over a time window, never revealing another customer's data, and only refunding delivered orders."
)


class CompileError(Exception):
    """Plain-language reason a policy could not be compiled. Maps to 422 COMPILE_FAILED."""


@dataclass
class Compiled:
    clauses: List[Clause]
    ambiguities: List[Ambiguity]
    patches: Dict[str, Dict[str, Any]]  # option_id -> param patch (server-side only)
    warnings: List[str] = field(default_factory=list)
    checks: List[Tuple[str, bool, str]] = field(default_factory=list)  # (check, passed, detail) shown to the reviewer


# ---------------------------------------------------------------- sentence splitting
def split_sentences(text: str) -> List[str]:
    out: List[str] = []
    for line in text.replace("\r", "").split("\n"):
        line = re.sub(r"^\s*(?:[-*\u2022\u25cf]+|\d{1,2}[.)])\s+", "", line).strip()
        if not line:
            continue
        parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\u20b9\"'])", line)
        out.extend(p.strip() for p in parts if p.strip())
    return out


_BULLET = re.compile(r"^\s*(?:[-*\u2022\u25cf\u25aa\u2013]+|\d{1,2}[.)]|[a-z][.)])\s+")


def unwrap_scanned_text(text: str) -> str:
    """A camera scan wraps one rule over several lines. Re-join a line with the next one unless the line ends a
    sentence or the next line starts a new list item, so each rule is one line again. Also drops scan noise."""
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in text.replace("\r", "").split("\n")]
    out: List[str] = []
    for line in lines:
        if not line:
            if out and out[-1] != "":
                out.append("")
            continue
        if len(re.sub(r"[^A-Za-z0-9]", "", line)) < 2:
            continue  # stray marks from the scan
        starts_item = bool(_BULLET.match(line))
        if out and out[-1] != "" and not starts_item and not re.search(r"[.!?:;]\s*$", out[-1]):
            out[-1] = f"{out[-1].rstrip('-') if out[-1].endswith('-') else out[-1] + ' '}{line}"
        else:
            out.append(_BULLET.sub("", line) if starts_item else line)
    cleaned = "\n".join(ln for ln in out if ln != "")
    # common scan confusions around the rupee sign
    cleaned = re.sub(r"\b(?:Rs|RS|INR)\s*\.?\s*(?=\d)", "\u20b9", cleaned)
    cleaned = re.sub(r"(\u20b9\d{1,3}) (\d{3})\b", r"\1,\2", cleaned)  # "\u20b95 000" -> "\u20b95,000"
    return cleaned.strip()


# ---------------------------------------------------------------- fixture parsing
_MULT = {"k": 1_000, "thousand": 1_000, "lakh": 100_000, "lakhs": 100_000}
_CUR_BEFORE = re.compile(r"(?:\u20b9|\brs\.?|\binr\b)\s*(\d[\d,]*(?:\.\d+)?)\s*(k|thousand|lakhs?)?", re.I)
_CUR_AFTER = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*(k|thousand|lakhs?)?\s*(?:\u20b9|\brs\b|\binr\b|\brupees?\b)", re.I)
_BARE = re.compile(r"(?<![\w-])(\d[\d,]{2,}|\d{3,})(?![\d,]*\s*(?:-|\s)?(?:hour|hr|day))", re.I)


_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
          "fifteen": 15, "twenty": 20, "twenty-five": 25, "thirty": 30, "forty": 40, "fifty": 50}
_WORD_AMOUNT = re.compile(r"\b(" + "|".join(_WORDS) + r")\s+(hundred|thousand|lakhs?)\b", re.I)
_WORD_MULT = {"hundred": 100, "thousand": 1_000, "lakh": 100_000, "lakhs": 100_000}


def _word_amounts(s: str) -> List[int]:
    return [_WORDS[m.group(1).lower()] * _WORD_MULT[m.group(2).lower()] for m in _WORD_AMOUNT.finditer(s)]


def _to_int(num: str, mult: Optional[str]) -> int:
    return int(round(float(num.replace(",", "")) * _MULT.get((mult or "").lower(), 1)))


def all_numbers(s: str) -> List[int]:
    """Every number written in a sentence (any style). Used to check that a proposed amount is really there."""
    found = [_to_int(m.group(1), m.group(2)) for m in _CUR_BEFORE.finditer(s)]
    found += [_to_int(m.group(1), m.group(2)) for m in _CUR_AFTER.finditer(s)]
    for m in re.finditer(r"(\d[\d,]*(?:\.\d+)?)\s*(k|thousand|lakhs?)?\b", s, re.I):
        try:
            found.append(_to_int(m.group(1), m.group(2)))
            found.append(_to_int(m.group(1), None))
        except ValueError:
            continue
    return found + _word_amounts(s)


def _amounts(s: str) -> List[int]:
    found = [_to_int(m.group(1), m.group(2)) for m in _CUR_BEFORE.finditer(s)]
    found += [_to_int(m.group(1), m.group(2)) for m in _CUR_AFTER.finditer(s)]
    if not found:
        found = _word_amounts(s)
    if not found:
        found = [_to_int(m.group(1), None) for m in _BARE.finditer(s)]
    return found


_OTHER = r"(?:another|other|different|any other)\s+(?:customer|user|client|account holder|person)|someone else"
_NEG = r"\b(never|not|no|don't|do not|must not|cannot|can't|shall not|mustn't)\b"
_REVEAL = r"\b(reveal|share|disclose|show|expose|leak|access|give|provide|return|display|send|tell|fetch|read)\b"
_UNDELIVERED = (
    r"(?:\bnot|n't|\bnever)\s+(?:yet\s+)?(?:been\s+)?deliver|undelivered|\bonly\b[^.]*\bdelivered|"
    r"\bunless\b[^.]*\bdelivered|before (?:it is |it has been |being )?deliver(?:ed|y)|prior to deliver|"
    r"until (?:it is |it has been |they are )?delivered|in transit|still shipping"
)
_REFUNDISH = r"refund|money back|reimburs|pay(?:ing)?\s?back|\bget\b.{0,60}?\bback\b|\bcredit(?:ed)? back\b"
_TOTALISH = r"\b(total|cumulative|aggregate|combined|altogether|sum|add up|added up|all refunds)\b"
_WINDOW = r"\b\d{1,3}[\s-]*(?:hour|hr)s?\b|\b(?:per|a|each|in any|any|one)\s+day\b|\bdaily\b|\bcalendar day\b|\b1[\s-]*day\b"
_LIMITISH = r"(exceed|no more than|at most|maximum|\bmax\b|limit|not more than|up to|capped|\bcap\b|under|below|within|not above|not over)"
_COMPARE = r"\b(above|over|more than|greater than|larger than|exceed(?:s|ing)?|beyond|higher than|bigger than)\b|>"
_APPROVAL = r"approv|human|manual|review|escalat|sign(?:ed)?[- ]?off|authori[sz]|\bcheck"


def parse_sentence(sentence: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    low = sentence.lower().replace("\u2019", "'")
    has_refund = bool(re.search(_REFUNDISH, low))
    if re.search(_NEG, low) and re.search(_REVEAL, low) and re.search(_OTHER, low):
        return "data_scope", {"subject": "session_customer"}
    if has_refund and re.search(_UNDELIVERED, low):
        return "precondition", {"field": "order.status", "operator": "eq", "value": "delivered"}
    amounts = _amounts(sentence)
    has_window = bool(re.search(_WINDOW, low))
    if has_refund and amounts and re.search(_TOTALISH, low) and has_window and re.search(_LIMITISH, low):
        hours = re.search(r"(\d+)[\s-]*(?:hour|hr)", low)
        return "cumulative_limit", {
            "field": "amount_inr", "max_total": amounts[0],
            "window_hours": int(hours.group(1)) if hours else 24,
            "window_type": "calendar_day" if re.search(r"calendar|midnight", low) else "rolling",
            "scope": "customer",
        }
    if has_refund and amounts and has_window and not re.search(_APPROVAL, low) and (
        re.search(_LIMITISH, low) or (re.search(_NEG, low) and re.search(_COMPARE, low))
    ):
        hours = re.search(r"(\d+)[\s-]*(?:hour|hr)", low)  # a limit over a time window, with no approval step: a total
        return "cumulative_limit", {
            "field": "amount_inr", "max_total": amounts[0],
            "window_hours": int(hours.group(1)) if hours else 24,
            "window_type": "calendar_day" if re.search(r"calendar|midnight", low) else "rolling",
            "scope": "customer",
        }
    if has_refund and amounts and re.search(_COMPARE, low) and re.search(_APPROVAL, low):
        per_customer = has_window or re.search(r"per (?:customer|user)", low)
        return "per_txn_limit", {
            "field": "amount_inr", "operator": "gt", "value": amounts[0],
            "scope": "customer_24h" if per_customer and not re.search(r"per (?:single )?(?:transaction|refund)", low) else "transaction",
        }
    return None


# ---------------------------------------------------------------- shared finalisation
def _rs(n: int) -> str:
    return f"\u20b9{n:,}"


def standard_ambiguity_spec(kind: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The two questions that are always asked, so a developer can never skip the scope/window decision."""
    if kind == "per_txn_limit":
        return {
            "question": f"Does the {_rs(params['value'])} limit apply to each single refund, or to a customer's refunds added up over 24 hours?",
            "options": [
                {"label": "Each single refund", "description": "Only the size of one refund is compared with the limit.", "param_patch": {"scope": "transaction"}},
                {"label": "Per customer over 24 hours", "description": "The customer's refunds in the last 24 hours plus this one are compared with the limit.", "param_patch": {"scope": "customer_24h"}},
            ],
            "default_index": 0 if params["scope"] == "transaction" else 1,
        }
    if kind == "cumulative_limit":
        hours = params["window_hours"]
        return {
            "question": f"Should the {hours}-hour window for the {_rs(params['max_total'])} total slide with time, or reset at midnight?",
            "options": [
                {"label": f"Rolling {hours} hours", "description": f"Counts refunds from the last {hours} hours, measured from each request.", "param_patch": {"window_type": "rolling"}},
                {"label": "Calendar day (UTC)", "description": "Counts refunds since midnight UTC and resets each day.", "param_patch": {"window_type": "calendar_day"}},
            ],
            "default_index": 0 if params["window_type"] == "rolling" else 1,
        }
    return None


def _validated_patch(clause: Clause, patch: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(patch, dict):
        raise CompileError("Compiler output was invalid (bad ambiguity option).")
    if not set(patch) <= ALLOWED_PATCH_KEYS:
        raise CompileError("Compiler output was invalid (an option tried to change something other than scope or window_type).")
    merged = {**clause.params.model_dump(), **patch}
    try:
        Clause(clause_id=clause.clause_id, source_sentence=clause.source_sentence, kind=clause.kind, action=clause.action, params=merged)
    except ValidationError as exc:
        raise CompileError("Compiler output was invalid (an option does not fit the rule it belongs to).") from exc
    return dict(patch)


def finalize(clause_specs: List[Tuple[str, str, Dict[str, Any]]], amb_specs: List[Dict[str, Any]],
             warnings: List[str], pack: Any = None) -> Compiled:
    """The gate every proposal passes (rule parser, server model, on-device model, imported clause file).

    clause_specs: (source_sentence, kind, params). amb_specs: {clause_index (0-based), question, options[], default_index}.
    """
    if pack is None:
        import packs

        pack = packs.get()
    if not clause_specs:
        raise CompileError(f"No supported rule was found in this policy. {pack.supported_text}")
    if len(clause_specs) > 50:
        raise CompileError("A policy can have at most 50 rules.")
    clauses: List[Clause] = []
    for i, (sentence, kind, params) in enumerate(clause_specs):
        if kind not in pack.kinds:
            raise CompileError(f"Rule {i + 1} uses a rule kind this agent does not support: {kind!r}. {pack.supported_text}")
        try:
            clauses.append(Clause(clause_id=f"C{i + 1}", source_sentence=sentence, kind=kind, action=KIND_ACTION.get(kind, "deny"), params=params))
        except ValidationError as exc:
            raise CompileError(f"Rule {i + 1} could not be compiled into a valid rule: {sentence!r}") from exc

    # keep supplied ambiguities (validated), then add the standard one where none covers that clause's decision
    per_clause: Dict[int, List[Dict[str, Any]]] = {}
    for spec in amb_specs:
        idx = spec.get("clause_index")
        if not isinstance(idx, int) or not 0 <= idx < len(clauses):
            raise CompileError("Compiler output was invalid (ambiguity points at a rule that does not exist).")
        opts = spec.get("options") or []
        if len(opts) < 2 or not isinstance(spec.get("question"), str) or not spec["question"].strip():
            raise CompileError("Compiler output was invalid (an ambiguity needs a question and two or more options).")
        keys = {k for o in opts for k in (o.get("param_patch") or {})}
        if any(keys & {k for o2 in prev["options"] for k in (o2.get("param_patch") or {})} for prev in per_clause.get(idx, [])) and keys:
            continue  # duplicate question about the same parameter
        per_clause.setdefault(idx, []).append(spec)
    for idx, clause in enumerate(clauses):
        std = pack.standard_ambiguity(clause.kind, clause.params.model_dump())
        if std is None:
            continue
        needed = {k for o in std["options"] for k in o["param_patch"]}
        covered = any(needed & {k for o in s["options"] for k in (o.get("param_patch") or {})} for s in per_clause.get(idx, []))
        if not covered:
            per_clause.setdefault(idx, []).append({"clause_index": idx, **std})

    ambiguities: List[Ambiguity] = []
    patches: Dict[str, Dict[str, Any]] = {}
    n = 0
    for idx in sorted(per_clause):
        for spec in per_clause[idx]:
            n += 1
            amb_id = f"A{n}"
            options: List[AmbiguityOption] = []
            for m, opt in enumerate(spec["options"], start=1):
                oid = f"{amb_id}_O{m}"
                patches[oid] = _validated_patch(clauses[idx], opt.get("param_patch") or {})
                options.append(AmbiguityOption(option_id=oid, label=str(opt.get("label", f"Option {m}"))[:120], description=str(opt.get("description", ""))[:300]))
            d = spec.get("default_index", 0)
            d = d if isinstance(d, int) and 0 <= d < len(options) else 0
            ambiguities.append(Ambiguity(
                ambiguity_id=amb_id, clause_id=clauses[idx].clause_id, question=spec["question"].strip()[:400],
                options=options, default_option_id=options[d].option_id,
            ))
    return Compiled(clauses=clauses, ambiguities=ambiguities, patches=patches, warnings=warnings)


def compile_fixture(policy_text: str, pack: Any = None) -> Compiled:
    if pack is None:
        import packs

        pack = packs.get()
    specs: List[Tuple[str, str, Dict[str, Any]]] = []
    skipped: List[str] = []
    for s in split_sentences(policy_text):
        parsed = pack.parse_sentence(s)
        if parsed:
            specs.append((s, parsed[0], parsed[1]))
        else:
            skipped.append(s)
    warnings = [f"Not a supported rule, so it was not compiled: \"{s}\"" for s in skipped] if specs else []
    compiled = finalize(specs, [], warnings, pack)
    compiled.checks = gate_checks(compiled, model_output=False)
    return compiled


def gate_checks(compiled: "Compiled", model_output: bool) -> List[Tuple[str, bool, str]]:
    """What the gate verified before a human sees the draft. Every entry is true by construction: a proposal
    that fails any of them never becomes a draft (it is rejected and the next provider answers instead)."""
    n = len(compiled.clauses)
    checks = []
    if model_output:
        checks.append(("json_object", True, "The model returned one JSON object and nothing else was used."))
    checks += [
        ("clause_schema", True, f"{n} rule(s) match the strict schema for their kind; unknown fields are rejected."),
        ("supported_kinds", True, "Every rule uses a kind this agent's engine implements."),
        ("fixed_actions", True, "What a broken rule does (deny or escalate) is fixed by its kind, not chosen by the proposer."),
    ]
    if model_output:
        checks += [
            ("cites_your_words", True, "Every rule cites a sentence that is really in your policy text."),
            ("numbers_grounded", True, "Every amount, count and window in a rule appears in the sentence it cites."),
            ("answer_options_bounded", True, "An answer option can only change scope, window, environments or mode."),
        ]
    checks.append(("ambiguities_asked", True, f"{len(compiled.ambiguities)} open question(s) must be answered by a human before approval."))
    return checks


# ---------------------------------------------------------------- approval
def apply_answers(clauses: List[Clause], ambiguities: List[Ambiguity], answers: Dict[str, str],
                  patches: Dict[str, Dict[str, Any]]) -> List[Clause]:
    by_id = {c.clause_id: c for c in clauses}
    params: Dict[str, Dict[str, Any]] = {c.clause_id: c.params.model_dump() for c in clauses}
    for amb in ambiguities:
        patch = patches.get(answers[amb.ambiguity_id], {})
        params[amb.clause_id].update(patch)
    out: List[Clause] = []
    for c in clauses:
        out.append(Clause(clause_id=c.clause_id, source_sentence=c.source_sentence, kind=c.kind, action=c.action, params=params[c.clause_id]))
    return out
