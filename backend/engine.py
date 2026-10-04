"""Deterministic core + the Engine that owns all state.

READ THIS FILE FIRST. Invariants - do not change without a contract discussion:
  * NO language model anywhere in evaluate() / _check() / run_call() or in any pack's validate_args / subject /
    check / execute. Plain code decides allow / deny / escalate.
  * Fail closed: anything unknown (tool, args, order, customer, service, secret) is deny with clause_id null.
  * deny beats escalate; among equals the lowest clause id wins.
  * Rolling window is (now - window, now]; an action exactly `window` old no longer counts.
  * Only EXECUTED actions enter the ledger. Denied / escalated calls never do.
  * A human approval releases an ESCALATE hold only. Every deny rule is checked again at release time.
  * Every state change (evaluate -> execute -> ledger) happens under one lock (_locked).

The engine is scenario-neutral. Everything specific to one kind of agent sits in a pack (packs.py).
"""
import difflib
import functools
import hashlib
import itertools
import json
import logging
import statistics
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import agent as agent_mod
import compiler as compiler_mod
import llm as llm_mod
import packs as packs_mod
from audit import AuditLog
from errors import ApiError, no_active_policy
from ledger import Ledger
from models import (
    CONTRACT_VERSION, Ambiguity, AmbiguityAnswer, Approval, ApprovalResolution, ApprovalsResponse, ApprovedPolicy,
    ApproveRequest, AuditResponse, AuditVerifyResponse, BenchItem, BenchRequest, BenchStatus, CaseCreate, CaseSpec,
    CasesResponse, ChatRequest, ChatResponse, CiRunRequest, CiRunResponse, Clause, CompileAttempt, CompileRequest,
    CompilerInfo, Decision, DecisionsResponse, DiffRow, GenerateRequest, GenerateResponse, GuardRequest,
    GuardResponse, Health, LocalModelConfig, ModelInfo, ModelsResponse, PolicyBundle, PolicyDiffResponse, PolicyDraft,
    PolicyHistoryResponse, PromptResponse, ResetRequest, ResetResponse, ResolveRequest, RollbackRequest,
    RunTestsRequest, Scenario, ScenarioStatus, ScenarioSummary, ScenariosResponse, TestReport, TextDiffLine,
    ValidationCheck,
)
from packs import Pack, Verdict, Violation

log = logging.getLogger("polyx.decisions")

MAX_TOOL_CALLS_PER_TURN = 4
MAX_LIVE_DECISIONS = 2000
MAX_HISTORY = 50
MAX_CUSTOM_CASES = 40
MAX_REPORTS = 60
MAX_DRAFTS = 200
RULES_LABEL = "Rule parser (deterministic, no model)"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """ISO-8601 UTC with millisecond precision and a trailing Z (e.g. 2026-09-21T07:27:51.897Z)."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _locked(fn):
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)

    return wrapper


_ID_LOCK = threading.Lock()
_ID_COUNTER = itertools.count(1)


def next_decision_id() -> str:
    with _ID_LOCK:
        return f"dec_{next(_ID_COUNTER):05d}"


# ====================================================================== deterministic evaluation
def _fail_closed(reason: str) -> Verdict:
    return Verdict("deny", None, None, reason)


def _validate_args(tool: Any, args: Any, pack: Optional[Pack] = None) -> Optional[str]:
    """Return an error message if the call is malformed, else None. Strict on purpose."""
    return (pack or packs_mod.get()).validate_args(tool, args)


def _check(clause: Clause, tool: str, args: Dict[str, Any], session_customer_id: str,
           subject_customer_id: Optional[str], ledger: Ledger, now: datetime,
           pack: Optional[Pack] = None) -> Optional[Violation]:
    """Evaluate ONE clause against ONE validated call. Pure code, no model."""
    return (pack or packs_mod.get()).check(clause, tool, args, session_customer_id, subject_customer_id, ledger, now)


def evaluate(tool: Any, args: Any, session_customer_id: str, clauses: List[Clause],
             ledger: Ledger, now: datetime, pack: Optional[Pack] = None, released: bool = False) -> Verdict:
    """The runtime decision. Deterministic. No model. Fails closed on anything unknown.

    released=True means a human approved this exact call from the inbox: escalate rules are satisfied,
    deny rules are not negotiable and are all checked again.
    """
    pack = pack or packs_mod.get()
    err = _validate_args(tool, args, pack)
    if err:
        return _fail_closed(err)
    subject, missing = pack.subject(tool, args, session_customer_id)
    if missing:
        return _fail_closed(missing)
    violations = [v for c in clauses if (v := _check(c, tool, args, session_customer_id, subject, ledger, now, pack))]
    if released:
        violations = [v for v in violations if v.clause.action != "escalate"]
    if not violations:
        return Verdict("allow", None, None, "No policy clause was violated.")
    # deny beats escalate; among equals the lowest clause id wins
    worst = min(violations, key=lambda v: (0 if v.clause.action == "deny" else 1, int(v.clause.clause_id[1:])))
    return Verdict(worst.clause.action, worst.clause.clause_id, worst.clause.source_sentence, worst.reason)


def _execute(tool: Any, args: Any, ledger: Ledger, now: datetime, pack: Optional[Pack] = None) -> Tuple[Dict[str, Any], bool]:
    """Run the simulated tool. Returns (tool_result, executed). Only successful actions touch the ledger."""
    return (pack or packs_mod.get()).execute(tool, args, ledger, now)


def _jsonable_args(args: Any) -> Dict[str, Any]:
    if not isinstance(args, dict):
        args = {"_raw": str(args)[:200]}
    try:
        json.dumps(args, allow_nan=False)
        return args
    except (TypeError, ValueError):
        return {str(k): (v if isinstance(v, (str, int, bool)) or v is None else str(v)) for k, v in args.items()}


def run_call(*, tool: Any, args: Any, session_customer_id: str, enforcement: str,
             policy: Optional[ApprovedPolicy], ledger: Ledger, now: datetime, decision_id: str,
             pack: Optional[Pack] = None, dry_run: bool = False, released_by: Optional[str] = None,
             ticket_id: Optional[str] = None) -> Decision:
    """Interceptor core: evaluate -> (execute | ticket | nothing) -> record. Caller holds the lock."""
    pack = pack or packs_mod.get()
    args = _jsonable_args(args)
    subject = pack.state_subject(tool, args, session_customer_id)
    state_before = pack.snapshot(ledger, subject, now, session_customer_id)
    if enforcement == "on":
        if policy is None:
            raise ValueError("enforcement 'on' requires a policy")
        t0 = time.perf_counter()
        verdict = evaluate(tool, args, session_customer_id, policy.clauses, ledger, now, pack, released_by is not None)
        latency_ms = round((time.perf_counter() - t0) * 1000, 4)
    else:
        verdict = Verdict("allow", None, None, "Enforcement is off: no policy check was made.")
        latency_ms = 0.0
    executed = False
    tool_result: Optional[Dict[str, Any]] = None
    reason = verdict.reason
    if dry_run:
        pass  # evaluate only: nothing runs, nothing is held, the ledger is untouched
    elif verdict.outcome == "allow":
        tool_result, executed = _execute(tool, args, ledger, now, pack)
        if released_by is not None:
            reason = f"Released by {released_by} from the approval inbox ({ticket_id}). Every deny rule was checked again and none was violated."
    elif verdict.outcome == "escalate":
        ticket_id = ledger.next_ticket_id()
        tool_result = {
            "status": "pending_approval",
            "ticket_id": ticket_id,
            "message": "Held for human approval. Nothing was executed.",
        }
    elif released_by is not None:
        reason = f"{released_by} approved {ticket_id}, but a deny rule still applies: {verdict.reason}"
    return Decision(
        decision_id=decision_id,
        timestamp=iso(now),
        tool=tool if isinstance(tool, str) else str(tool),
        args=args,
        session_customer_id=session_customer_id,
        enforced=enforcement == "on",
        outcome=verdict.outcome,
        executed=executed,
        clause_id=verdict.clause_id,
        source_sentence=verdict.source_sentence,
        reason=reason,
        policy_version=policy.policy_version if (enforcement == "on" and policy) else None,
        state_before=state_before,
        state_after=pack.snapshot(ledger, subject, now, session_customer_id),
        latency_ms=latency_ms,
        tool_result=tool_result,
        scenario_id=pack.id,
        ticket_id=ticket_id,
        approved_by=released_by,
        dry_run=dry_run,
    )


# ====================================================================== policy diff
def _norm(s: str) -> str:
    return " ".join(s.split()).lower()


def diff_policies(old: List[Clause], new: List[Clause]) -> List[DiffRow]:
    old_by = {_norm(c.source_sentence): c for c in old}
    rows: List[DiffRow] = []
    seen = set()
    for c in new:
        key = _norm(c.source_sentence)
        o = old_by.get(key)
        if o is None:
            rows.append(DiffRow(clause_id=c.clause_id, change="added", source_sentence=c.source_sentence, detail=None))
            continue
        seen.add(key)
        if o.kind == c.kind and o.params == c.params:
            rows.append(DiffRow(clause_id=c.clause_id, change="unchanged", source_sentence=c.source_sentence, detail=None))
        else:
            a, b = o.params.model_dump(), c.params.model_dump()
            detail = "; ".join(f"{k}: {a.get(k)} -> {b.get(k)}" for k in b if a.get(k) != b.get(k)) or "rule changed"
            rows.append(DiffRow(clause_id=c.clause_id, change="changed", source_sentence=c.source_sentence, detail=detail))
    for key, o in old_by.items():
        if key not in seen:
            rows.append(DiffRow(clause_id=o.clause_id, change="removed", source_sentence=o.source_sentence, detail=None))
    return rows


def bundle_checksum(scenario_id: str, policy_text: str, clauses: List[Clause]) -> str:
    canon = json.dumps({"scenario_id": scenario_id, "policy_text": policy_text.strip(),
                        "clauses": [c.model_dump() for c in clauses]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ====================================================================== the engine
@dataclass
class _DraftRecord:
    draft: PolicyDraft
    patches: Dict[str, Dict[str, Any]]  # option_id -> internal param_patch. NEVER sent to clients.
    approved: bool = False


class Engine:
    def __init__(self, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._lock = threading.RLock()
        self.clock = clock or utcnow
        self._started = time.monotonic()
        self.packs: Dict[str, Pack] = {p.id: p for p in packs_mod.all_packs()}
        self.ledgers: Dict[str, Ledger] = {p.id: Ledger(p.receipt_prefix, p.ticket_prefix) for p in self.packs.values()}
        self.decisions: List[Decision] = []
        self.drafts: Dict[str, _DraftRecord] = {}
        self.actives: Dict[str, Optional[ApprovedPolicy]] = {pid: None for pid in self.packs}
        self.history: Dict[str, List[ApprovedPolicy]] = {pid: [] for pid in self.packs}
        self._version_seq: Dict[str, int] = {pid: 0 for pid in self.packs}
        self._draft_seq = 0
        self._report_seq = 0
        self._ci_seq = 0
        self.reports: Dict[str, TestReport] = {}
        self.latest_report_id: Optional[str] = None
        self.latest_report_ids: Dict[str, Optional[str]] = {pid: None for pid in self.packs}
        self.providers: Dict[str, llm_mod.Provider] = {}
        self.provider_order: List[str] = llm_mod.provider_order()
        self.approvals: Dict[str, Approval] = {}
        self.custom_cases: Dict[str, List[CaseSpec]] = {pid: [] for pid in self.packs}
        self._case_seq: Dict[str, Dict[str, int]] = {pid: {"U": 0, "G": 0} for pid in self.packs}
        self._gen_cursor: Dict[str, int] = {pid: 0 for pid in self.packs}
        self.audit = AuditLog()
        self.bench: Optional[BenchStatus] = None
        self._bench_seq = 0
        self.auto_armed = False
        self.admin_token: Optional[str] = None

    # ---------------------------------------------------------------- v1.0.0 views (support pack)
    @property
    def ledger(self) -> Ledger:
        return self.ledgers[packs_mod.DEFAULT_PACK_ID]

    @property
    def active(self) -> Optional[ApprovedPolicy]:
        return self.actives[packs_mod.DEFAULT_PACK_ID]

    @active.setter
    def active(self, value: Optional[ApprovedPolicy]) -> None:
        self.actives[packs_mod.DEFAULT_PACK_ID] = value

    @property
    def llm_available(self) -> bool:
        return any(p.available and p.client is not None for p in self.providers.values())

    @property
    def llm_client(self) -> Any:
        chain = self._chain("auto")
        return chain[0].client if chain else None

    def _pack(self, scenario_id: Optional[str]) -> Pack:
        pack = self.packs.get(scenario_id or packs_mod.DEFAULT_PACK_ID)
        if pack is None:
            raise ApiError("SCENARIO_NOT_FOUND", f"Scenario '{scenario_id}' was not found. Known scenarios: {', '.join(self.packs)}.", 404,
                           {"scenarios": list(self.packs)})
        return pack

    def _audit(self, type_: str, summary: str, scenario_id: Optional[str] = None, actor: str = "system",
               data: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self.audit.append(iso(self.clock()), type_, summary, scenario_id, actor, data)

    # ---------------------------------------------------------------- simple reads
    @_locked
    def health(self) -> Health:
        return Health(
            status="ok", contract_version=CONTRACT_VERSION, llm_available=self.llm_available,
            active_policy_version=self.active.policy_version if self.active else None,
            service="poly-x", uptime_s=round(time.monotonic() - self._started, 1),
            scenarios=[ScenarioStatus(scenario_id=p.id, title=p.title,
                                      active_policy_version=self.actives[p.id].policy_version if self.actives[p.id] else None)
                       for p in self.packs.values()],
            models=self._model_infos(),
            pending_approvals=sum(a.status == "pending" for a in self.approvals.values()),
            auto_armed=self.auto_armed,
        )

    def scenario(self, scenario_id: Optional[str] = None) -> Scenario:
        return Scenario(**self._pack(scenario_id).scenario())

    @_locked
    def scenarios(self) -> ScenariosResponse:
        return ScenariosResponse(
            default_scenario_id=packs_mod.DEFAULT_PACK_ID,
            scenarios=[ScenarioSummary(
                scenario_id=p.id, title=p.title, description=p.description, actor_label=p.actor_label,
                tools=[t["name"] for t in p.tool_specs], clause_kinds=p.kinds,
                active_policy_version=self.actives[p.id].policy_version if self.actives[p.id] else None,
                builtin_cases=len(p.builtin_cases()), custom_cases=len(self.custom_cases[p.id]),
            ) for p in self.packs.values()],
        )

    # ---------------------------------------------------------------- model providers
    def set_llm(self, client: Any, available: bool) -> None:
        """v1.0.0 hook: install one verified client as the cloud provider."""
        with self._lock:
            if not available or client is None:
                self.providers.pop("cloud", None)
                return
            prov = llm_mod.make_provider("cloud", llm_mod._env("LLM_BASE_URL", default=llm_mod.GROQ_BASE_URL), llm_mod.MODEL)
            prov.client, prov.available, prov.last_checked = client, True, time.time()
            self.providers["cloud"] = prov

    def set_provider(self, provider: llm_mod.Provider) -> None:
        with self._lock:
            self.providers[provider.name] = provider

    def init_providers(self) -> None:
        """Read the environment and probe each configured provider. Slow (network): call it off the event loop."""
        for prov in llm_mod.providers_from_env():
            llm_mod.probe(prov)
            self.set_provider(prov)
            log.info("provider %s model=%s available=%s error=%s", prov.name, prov.model, prov.available, prov.last_error)

    def refresh_models(self) -> ModelsResponse:
        with self._lock:
            provs = list(self.providers.values())
        for prov in provs:
            if isinstance(prov.client, llm_mod.OpenAICompatClient) or prov.client is None:
                llm_mod.probe(prov)
        return self.models()

    def set_local_model(self, cfg: LocalModelConfig) -> ModelsResponse:
        if not cfg.base_url.lower().startswith(("http://", "https://")):
            raise ApiError("VALIDATION_ERROR", "base_url must start with http:// or https://.", 422, {"fields": ["base_url"]})
        prov = llm_mod.make_provider("local", cfg.base_url, cfg.model, cfg.api_key)
        llm_mod.probe(prov)
        self.set_provider(prov)
        self._audit("model.configured", f"Local model set to {cfg.model} on {prov.host} (available: {prov.available}).",
                    actor="admin", data={"model": cfg.model, "host": prov.host, "available": prov.available})
        return self.models()

    def _model_infos(self) -> List[ModelInfo]:
        out: List[ModelInfo] = []
        for name in self.provider_order:
            p = self.providers.get(name)
            if p is None:
                out.append(ModelInfo(
                    provider=name, label="Local open-source model" if name == "local" else "Cloud open-weight model",
                    model=None, host=None, location=name, configured=False, available=False,
                    last_checked_at=None, last_error=None, latency_ms=None))
                continue
            checked = iso(datetime.fromtimestamp(p.last_checked, timezone.utc)) if p.last_checked else None
            out.append(ModelInfo(provider=name, label=p.label, model=p.model, host=p.host, location=p.location,
                                 configured=True, available=p.available and p.client is not None,
                                 last_checked_at=checked, last_error=p.last_error, latency_ms=p.latency_ms))
        out.append(ModelInfo(provider="rules", label=RULES_LABEL, model=None, host=None, location="server",
                             configured=True, available=True, last_checked_at=None, last_error=None, latency_ms=None))
        return out

    @_locked
    def models(self) -> ModelsResponse:
        return ModelsResponse(providers=self._model_infos(), order=self.provider_order + ["rules"],
                              runtime_config_enabled=bool(self.admin_token))

    def _chain(self, choice: Optional[str]) -> List[llm_mod.Provider]:
        """Providers to try, in order. An explicit choice goes first; the rest follow as automatic fallback."""
        if choice == "fixture":
            return []
        with self._lock:
            live = {n: p for n, p in self.providers.items() if p.available and p.client is not None}
            order = list(self.provider_order)
        if choice in ("local", "cloud"):
            order = [choice] + [n for n in order if n != choice]
        return [live[n] for n in order if n in live]

    def prompt(self, scenario_id: Optional[str]) -> PromptResponse:
        import compiler_llm

        pack = self._pack(scenario_id)
        return PromptResponse(scenario_id=pack.id, system_prompt=pack.llm_system_prompt(),
                              user_template=compiler_llm.USER_TEMPLATE, clause_kinds=pack.kinds)

    # ---------------------------------------------------------------- compile / approve
    def _compile_text(self, text: str, pack: Pack, choice: Optional[str], proposal: Any = None,
                      proposal_model: Optional[str] = None) -> Tuple[compiler_mod.Compiled, str, CompilerInfo, List[str]]:
        """Proposal step. Returns (compiled, compiled_by, compiler info, extra warnings). Raises CompileError."""
        import compiler_llm  # local import: keeps the model code out of the deterministic path

        attempts: List[CompileAttempt] = []
        warnings: List[str] = []
        t_all = time.perf_counter()

        def info(provider: str, model: Optional[str], location: str, label: str) -> CompilerInfo:
            return CompilerInfo(provider=provider, model=model, location=location, label=label,
                                latency_ms=round((time.perf_counter() - t_all) * 1000, 1), attempts=attempts)

        def record(provider: str, model: Optional[str], t0: float, error: Optional[str]) -> None:
            attempts.append(CompileAttempt(provider=provider, model=model, ok=error is None,
                                           latency_ms=round((time.perf_counter() - t0) * 1000, 1), error=error))

        def rules() -> Optional[compiler_mod.Compiled]:
            try:
                return compiler_mod.compile_fixture(text, pack)
            except compiler_mod.CompileError:
                return None

        if proposal is not None:  # proposed by a model running on the user's device
            t0 = time.perf_counter()
            try:
                compiled = compiler_llm.finalize_proposal(text, compiler_llm.parse_proposal(proposal), pack)
                record("device", proposal_model, t0, None)
                return compiled, "llm", info("device", proposal_model, "on_device", f"On-device model \u00b7 {proposal_model or 'unnamed'}"), warnings
            except (compiler_llm.LLMCompileError, compiler_mod.CompileError) as exc:
                record("device", proposal_model, t0, str(exc)[:200])
                warnings.append("The on-device model's proposal did not pass the gate, so the built-in rule parser (fixture compiler) produced the rules instead.")
        else:
            wanted = choice if choice in ("local", "cloud") else None
            chain = self._chain(choice)
            if wanted and (not chain or chain[0].name != wanted):
                warnings.append(f"The {wanted} model is not reachable right now, so another compiler answered.")
            for prov in chain:
                t0 = time.perf_counter()
                try:
                    compiled = compiler_llm.propose_and_finalize(text, prov.client, pack, prov.model, prov.compile_timeout_s)
                    record(prov.name, prov.model, t0, None)
                    return compiled, "llm", info(prov.name, prov.model, prov.location, f"{prov.label} \u00b7 {prov.model}"), warnings
                except compiler_mod.CompileError as exc:
                    # The model read the policy and found nothing it supports. Believe it only if the
                    # deterministic parser agrees; a small model missing an obvious rule must not fail the user.
                    record(prov.name, prov.model, t0, "found no supported rule")
                    fallback = rules()
                    if fallback is None:
                        raise exc
                    warnings.append(f"The {prov.name} model found no supported rule, but the built-in rule parser (fixture compiler) did; its rules are shown instead.")
                    record("rules", None, time.perf_counter(), None)
                    return fallback, "fixture", info("rules", None, "server", RULES_LABEL), warnings
                except Exception as exc:  # noqa: BLE001 - any model failure falls through, labelled
                    record(prov.name, prov.model, t0, f"{type(exc).__name__}: {str(exc)[:160]}")
                    warnings.append(f"LLM compile failed on the {prov.name} model ({type(exc).__name__}); trying the next compiler.")
                    log.warning("llm compile failed on %s: %s", prov.name, exc)
            if attempts:
                warnings.append("No model produced valid rules, so they were produced by the built-in rule parser (fixture compiler) instead.")
        t0 = time.perf_counter()
        compiled = compiler_mod.compile_fixture(text, pack)  # raises CompileError -> COMPILE_FAILED
        record("rules", None, t0, None)
        return compiled, "fixture", info("rules", None, "server", RULES_LABEL), warnings

    def compile(self, req: CompileRequest) -> PolicyDraft:
        """A model proposes (when one is reachable); the rule parser is the labelled fallback.
        Nothing here deploys anything: approval is a separate human step."""
        pack = self._pack(req.scenario)
        text = req.policy_text.strip()
        if req.source == "ocr":
            text = compiler_mod.unwrap_scanned_text(text) or text
        choice = "fixture" if req.mode == "fixture" and req.provider is None else (req.provider or "auto")
        compiled, compiled_by, compiler, extra = self._compile_text(text, pack, choice, req.proposal, req.proposal_model)
        if req.source == "ocr":
            extra.append("This text came from a camera scan. Check each rule against the page before you approve.")
        with self._lock:
            self._draft_seq += 1
            draft = PolicyDraft(
                policy_id=f"pol_{self._draft_seq:03d}", created_at=iso(self.clock()), policy_text=text,
                compiled_by=compiled_by, clauses=compiled.clauses, ambiguities=compiled.ambiguities,
                warnings=list(compiled.warnings) + extra, scenario_id=pack.id, compiler=compiler,
                validation=[ValidationCheck(check=c, passed=ok, detail=d) for c, ok, d in compiled.checks],
                source=req.source,
            )
            self._store_draft(draft, compiled.patches)
            self._audit("policy.compiled", f"Draft {draft.policy_id}: {len(draft.clauses)} rule(s) proposed by {compiler.label}.",
                        pack.id, "developer", {"policy_id": draft.policy_id, "compiled_by": compiled_by,
                                               "provider": compiler.provider, "model": compiler.model, "source": req.source})
            return draft

    def _store_draft(self, draft: PolicyDraft, patches: Dict[str, Dict[str, Any]]) -> None:
        self.drafts[draft.policy_id] = _DraftRecord(draft=draft, patches=patches)
        if len(self.drafts) > MAX_DRAFTS:
            for key in list(self.drafts)[: len(self.drafts) - MAX_DRAFTS]:
                del self.drafts[key]

    @_locked
    def approve(self, policy_id: str, req: ApproveRequest, note: Optional[str] = None) -> ApprovedPolicy:
        rec = self.drafts.get(policy_id)
        if rec is None:
            raise ApiError("POLICY_NOT_FOUND", f"Policy {policy_id} was not found.", 404)
        if rec.approved:
            raise ApiError("POLICY_ALREADY_APPROVED", f"Policy {policy_id} was already approved. Compile it again to change it.", 409)
        answers = self._check_answers(rec.draft.ambiguities, req.answers)
        missing = [a.ambiguity_id for a in rec.draft.ambiguities if a.ambiguity_id not in answers]
        if missing:
            raise ApiError(
                "AMBIGUITY_UNRESOLVED",
                f"{len(missing)} question(s) still need an answer before this policy can be approved.",
                422, {"missing_ambiguity_ids": missing},
            )
        clauses = compiler_mod.apply_answers(rec.draft.clauses, rec.draft.ambiguities, answers, rec.patches)
        pid = rec.draft.scenario_id
        self._version_seq[pid] += 1
        previous = self.actives[pid].clauses if self.actives[pid] else []
        approved = ApprovedPolicy(
            policy_id=policy_id, policy_version=self._version_seq[pid], approved_at=iso(self.clock()),
            policy_text=rec.draft.policy_text, compiled_by=rec.draft.compiled_by, clauses=clauses,
            answers=[AmbiguityAnswer(ambiguity_id=k, option_id=answers[k]) for k in sorted(answers)],
            diff=diff_policies(previous, clauses), scenario_id=pid, compiler=rec.draft.compiler,
            approved_by=req.approved_by or "reviewer", note=note,
        )
        rec.approved = True
        self.actives[pid] = approved
        self.history[pid].append(approved)
        if len(self.history[pid]) > MAX_HISTORY:
            del self.history[pid][: len(self.history[pid]) - MAX_HISTORY]
        self._audit("policy.approved", f"Policy v{approved.policy_version} approved by {approved.approved_by} ({len(clauses)} rule(s)).",
                    pid, approved.approved_by, {"policy_id": policy_id, "policy_version": approved.policy_version,
                                                "checksum": bundle_checksum(pid, approved.policy_text, clauses),
                                                "answers": {k: answers[k] for k in sorted(answers)}})
        return approved

    @staticmethod
    def _check_answers(ambiguities: List[Ambiguity], given: List[AmbiguityAnswer]) -> Dict[str, str]:
        amb_by_id: Dict[str, Ambiguity] = {a.ambiguity_id: a for a in ambiguities}
        answers: Dict[str, str] = {}
        for ans in given:
            amb = amb_by_id.get(ans.ambiguity_id)
            if amb is None or ans.option_id not in {o.option_id for o in amb.options} or (
                ans.ambiguity_id in answers and answers[ans.ambiguity_id] != ans.option_id
            ):
                raise ApiError(
                    "VALIDATION_ERROR",
                    "Each answer must name a real ambiguity_id and one of its option_ids, once.",
                    422, {"fields": ["answers"]},
                )
            answers[ans.ambiguity_id] = ans.option_id
        return answers

    @_locked
    def active_policy(self, scenario_id: Optional[str] = None) -> ApprovedPolicy:
        active = self.actives[self._pack(scenario_id).id]
        if active is None:
            raise no_active_policy(404)
        return active

    def auto_arm(self) -> None:
        """Approve each scenario's default policy with default answers, so a cold restart is never 'no policy'.
        Labelled: approved_by is 'auto-arm' and the audit trail says so."""
        for pack in self.packs.values():
            with self._lock:
                if self.actives[pack.id] is not None:
                    continue
            draft = self.compile(CompileRequest(policy_text=pack.default_policy_text, mode="fixture", scenario=pack.id))
            answers = [AmbiguityAnswer(ambiguity_id=a.ambiguity_id, option_id=a.default_option_id) for a in draft.ambiguities]
            self.approve(draft.policy_id, ApproveRequest(answers=answers, approved_by="auto-arm"),
                         note="Default policy approved automatically at startup with default answers.")
        self.auto_armed = True

    # ---------------------------------------------------------------- policy as code
    @_locked
    def policy_history(self, scenario_id: Optional[str]) -> PolicyHistoryResponse:
        pid = self._pack(scenario_id).id
        active = self.actives[pid]
        return PolicyHistoryResponse(scenario_id=pid, versions=list(reversed(self.history[pid])),
                                     active_policy_version=active.policy_version if active else None)

    def _version(self, pid: str, version: int) -> ApprovedPolicy:
        for p in self.history[pid]:
            if p.policy_version == version:
                return p
        raise ApiError("VERSION_NOT_FOUND", f"Policy version {version} was not found for scenario '{pid}'.", 404)

    @_locked
    def policy_version(self, scenario_id: Optional[str], version: int) -> ApprovedPolicy:
        return self._version(self._pack(scenario_id).id, version)

    @_locked
    def policy_diff(self, scenario_id: Optional[str], from_version: int, to_version: int) -> PolicyDiffResponse:
        pid = self._pack(scenario_id).id
        a, b = self._version(pid, from_version), self._version(pid, to_version)
        a_lines, b_lines = a.policy_text.splitlines(), b.policy_text.splitlines()
        text_diff: List[TextDiffLine] = []
        for line in difflib.ndiff(a_lines, b_lines):
            if line.startswith("? "):
                continue
            text_diff.append(TextDiffLine(op={"  ": "same", "+ ": "add", "- ": "remove"}[line[:2]], text=line[2:]))
        unified = "\n".join(difflib.unified_diff(a_lines, b_lines, f"policy.md (v{from_version})", f"policy.md (v{to_version})", lineterm=""))
        return PolicyDiffResponse(scenario_id=pid, from_version=from_version, to_version=to_version,
                                  clause_diff=diff_policies(a.clauses, b.clauses), text_diff=text_diff, unified=unified)

    @_locked
    def export_policy(self, scenario_id: Optional[str], version: Optional[int] = None) -> PolicyBundle:
        pid = self._pack(scenario_id).id
        if version is None:
            pol = self.actives[pid]
            if pol is None:
                raise no_active_policy(404)
        else:
            pol = self._version(pid, version)
        return PolicyBundle(format="polyx.policy/v1", scenario_id=pid, policy_version=pol.policy_version,
                            policy_text=pol.policy_text, clauses=pol.clauses, compiled_by=pol.compiled_by,
                            exported_at=iso(self.clock()), checksum=bundle_checksum(pid, pol.policy_text, pol.clauses))

    def import_policy(self, bundle: PolicyBundle) -> PolicyDraft:
        """A committed clause file comes back as a DRAFT. It passes the same gate and still needs a human approval."""
        pack = self._pack(bundle.scenario_id)
        text = bundle.policy_text.strip()
        warnings: List[str] = []
        if bundle.checksum and bundle.checksum != bundle_checksum(pack.id, text, bundle.clauses):
            warnings.append("The file's checksum does not match its contents: it was edited after export. Review every rule.")
        sentences = {_norm(s) for s in compiler_mod.split_sentences(text)}
        for c in bundle.clauses:
            if _norm(c.source_sentence) not in sentences:
                raise ApiError("IMPORT_INVALID", f"Rule {c.clause_id} cites a sentence that is not in the policy text: \"{c.source_sentence[:80]}\"", 422,
                               {"clause_id": c.clause_id})
        try:
            compiled = compiler_mod.finalize([(c.source_sentence, c.kind, c.params.model_dump()) for c in bundle.clauses], [], warnings, pack)
        except compiler_mod.CompileError as exc:
            raise ApiError("IMPORT_INVALID", str(exc), 422) from exc
        compiled.checks = compiler_mod.gate_checks(compiled, model_output=False)
        compiler = CompilerInfo(provider="import", model=None, location="server", label="Imported clause file", latency_ms=0.0,
                                attempts=[CompileAttempt(provider="import", model=None, ok=True, latency_ms=0.0, error=None)])
        with self._lock:
            self._draft_seq += 1
            draft = PolicyDraft(
                policy_id=f"pol_{self._draft_seq:03d}", created_at=iso(self.clock()), policy_text=text, compiled_by="import",
                clauses=compiled.clauses, ambiguities=compiled.ambiguities, warnings=compiled.warnings, scenario_id=pack.id,
                compiler=compiler, validation=[ValidationCheck(check=c, passed=ok, detail=d) for c, ok, d in compiled.checks],
                source="file",
            )
            self._store_draft(draft, compiled.patches)
            self._audit("policy.imported", f"Draft {draft.policy_id} imported from a clause file ({len(draft.clauses)} rule(s)).",
                        pack.id, "developer", {"policy_id": draft.policy_id, "checksum_ok": not warnings})
            return draft

    def rollback(self, req: RollbackRequest) -> ApprovedPolicy:
        pid = self._pack(req.scenario).id
        with self._lock:
            old = self._version(pid, req.version)
        draft = self.import_policy(PolicyBundle(format="polyx.policy/v1", scenario_id=pid, policy_text=old.policy_text, clauses=old.clauses))
        answers = [AmbiguityAnswer(ambiguity_id=a.ambiguity_id, option_id=a.default_option_id) for a in draft.ambiguities]
        return self.approve(draft.policy_id, ApproveRequest(answers=answers, approved_by=req.approved_by or "reviewer"),
                            note=f"Rolled back to the rules of v{req.version}.")

    # ---------------------------------------------------------------- the interceptor
    def _record(self, d: Decision) -> None:
        self.decisions.append(d)
        if len(self.decisions) > MAX_LIVE_DECISIONS:
            del self.decisions[: len(self.decisions) - MAX_LIVE_DECISIONS]
        self.audit.append(d.timestamp, "decision", f"{d.tool} -> {d.outcome}" + (f" ({d.clause_id})" if d.clause_id else ""),
                          d.scenario_id, d.session_customer_id,
                          {"decision_id": d.decision_id, "tool": d.tool, "args": d.args, "outcome": d.outcome, "executed": d.executed,
                           "enforced": d.enforced, "clause_id": d.clause_id, "policy_version": d.policy_version,
                           "ticket_id": d.ticket_id, "approved_by": d.approved_by})
        log.info("decision %s scenario=%s tool=%s outcome=%s clause=%s executed=%s enforced=%s",
                 d.decision_id, d.scenario_id, d.tool, d.outcome, d.clause_id, d.executed, d.enforced)

    @_locked
    def call(self, tool: Any, args: Any, session_customer_id: str, enforcement: str = "on",
             now: Optional[datetime] = None, scenario_id: Optional[str] = None, dry_run: bool = False) -> Decision:
        """EVERY tool call (naive agent, model agent, guard API) goes through here. Nothing touches a tool directly."""
        pack = self._pack(scenario_id)
        policy = self.actives[pack.id]
        if enforcement == "on" and policy is None:
            raise no_active_policy(409)
        d = run_call(
            tool=tool, args=args, session_customer_id=session_customer_id, enforcement=enforcement,
            policy=policy if enforcement == "on" else None, ledger=self.ledgers[pack.id],
            now=now or self.clock(), decision_id=next_decision_id(), pack=pack, dry_run=dry_run,
        )
        if dry_run:
            return d
        self._record(d)
        if d.outcome == "escalate" and d.ticket_id:
            self.approvals[d.ticket_id] = Approval(
                ticket_id=d.ticket_id, scenario_id=pack.id, status="pending", created_at=d.timestamp,
                decision_id=d.decision_id, tool=d.tool, args=d.args, session_customer_id=d.session_customer_id,
                summary=pack.describe_call(d.tool, d.args), clause_id=d.clause_id, source_sentence=d.source_sentence,
                reason=d.reason, policy_version=d.policy_version, resolved_at=None, resolved_by=None, note=None,
                result_decision_id=None, result_outcome=None, result_reason=None,
            )
            self.audit.append(d.timestamp, "approval.created", f"{d.ticket_id}: {pack.describe_call(d.tool, d.args)} is waiting for a human.",
                              pack.id, d.session_customer_id, {"ticket_id": d.ticket_id, "decision_id": d.decision_id, "clause_id": d.clause_id})
        return d

    def guard(self, req: GuardRequest) -> GuardResponse:
        pack = self._pack(req.scenario)
        session = req.session_customer_id or pack.session_id
        if session not in pack.actors:
            raise ApiError("CUSTOMER_NOT_FOUND", f"{pack.actor_label.capitalize()} {session} was not found.", 404)
        d = self.call(req.tool, req.args, session, "on", scenario_id=pack.id, dry_run=req.dry_run)
        return GuardResponse(
            allowed=d.outcome == "allow", outcome=d.outcome, executed=d.executed, clause_id=d.clause_id,
            source_sentence=d.source_sentence, reason=d.reason, ticket_id=d.ticket_id, policy_version=d.policy_version,
            latency_ms=d.latency_ms, dry_run=req.dry_run, decision=d,
        )

    # ---------------------------------------------------------------- approval inbox
    @_locked
    def list_approvals(self, status: Optional[str] = None, scenario_id: Optional[str] = None, limit: int = 50) -> ApprovalsResponse:
        if scenario_id is not None:
            self._pack(scenario_id)
        items = [a for a in reversed(list(self.approvals.values()))
                 if (status is None or a.status == status) and (scenario_id is None or a.scenario_id == scenario_id)]
        return ApprovalsResponse(approvals=items[:limit], pending=sum(a.status == "pending" for a in self.approvals.values()), total=len(items))

    @_locked
    def get_approval(self, ticket_id: str) -> Approval:
        ap = self.approvals.get(ticket_id)
        if ap is None:
            raise ApiError("APPROVAL_NOT_FOUND", f"Approval {ticket_id} was not found. It may have been cleared by a reset.", 404)
        return ap

    @_locked
    def resolve_approval(self, ticket_id: str, req: ResolveRequest) -> ApprovalResolution:
        ap = self.get_approval(ticket_id)
        if ap.status != "pending":
            raise ApiError("APPROVAL_ALREADY_RESOLVED", f"Approval {ticket_id} was already {ap.status} by {ap.resolved_by}.", 409,
                           {"status": ap.status, "resolved_by": ap.resolved_by})
        now = self.clock()
        pack = self._pack(ap.scenario_id)
        decision: Optional[Decision] = None
        update: Dict[str, Any] = {"resolved_at": iso(now), "resolved_by": req.approver, "note": req.note}
        if req.action == "reject":
            update["status"] = "rejected"
            summary = f"{ticket_id} rejected by {req.approver}. Nothing was executed."
        else:
            policy = self.actives[pack.id]
            if policy is None:
                raise no_active_policy(409)
            decision = run_call(
                tool=ap.tool, args=ap.args, session_customer_id=ap.session_customer_id, enforcement="on", policy=policy,
                ledger=self.ledgers[pack.id], now=now, decision_id=next_decision_id(), pack=pack,
                released_by=req.approver, ticket_id=ticket_id,
            )
            self._record(decision)
            update.update(status="approved", result_decision_id=decision.decision_id,
                          result_outcome=decision.outcome, result_reason=decision.reason)
            summary = (f"{ticket_id} approved by {req.approver}; the call ran." if decision.executed
                       else f"{ticket_id} approved by {req.approver}, but a deny rule still blocked it.")
        ap = ap.model_copy(update=update)
        self.approvals[ticket_id] = ap
        self.audit.append(iso(now), "approval.resolved", summary, pack.id, req.approver,
                          {"ticket_id": ticket_id, "action": req.action, "note": req.note,
                           "result_decision_id": ap.result_decision_id, "result_outcome": ap.result_outcome})
        return ApprovalResolution(approval=ap, decision=decision)

    # ---------------------------------------------------------------- live chat
    def chat(self, req: ChatRequest) -> ChatResponse:
        pack = self._pack(req.scenario)
        cid = req.session_customer_id or pack.session_id
        if cid not in pack.actors:
            raise ApiError("CUSTOMER_NOT_FOUND", f"{pack.actor_label.capitalize()} {cid} was not found.", 404)
        with self._lock:
            active = self.actives[pack.id]
            if req.enforcement == "on" and active is None:
                raise no_active_policy(409)
        chain = self._chain(req.provider) if req.agent_mode in ("auto", "llm") else []
        policy_text = active.policy_text if active else pack.default_policy_text

        collected: List[Decision] = []

        def call_fn(tool: Any, args: Any) -> Decision:
            d = self.call(tool, args, cid, req.enforcement, scenario_id=pack.id)  # the ONLY route to a tool
            collected.append(d)
            return d

        note: Optional[str] = None
        mode_used = "naive"
        reply: Optional[str] = None
        agent_model: Optional[str] = None
        if chain:
            prov = chain[0]
            try:
                reply = agent_mod.run_llm_agent(prov.client, req.message, cid, policy_text, call_fn, MAX_TOOL_CALLS_PER_TURN,
                                                pack, prov.model, prov.agent_timeout_s)
                mode_used, agent_model = "llm", prov.model
            except Exception as exc:  # noqa: BLE001
                log.warning("llm agent failed: %s", exc)
                if collected:
                    # Tools already ran through call(); re-running the naive agent would repeat them.
                    reply = " ".join(pack.describe(d) for d in collected)
                    mode_used, agent_model = "llm", prov.model
                    note = f"The LLM agent errored after {len(collected)} tool call(s) ({type(exc).__name__}); showing what was executed. Not re-run."
                else:
                    note = f"LLM agent failed ({type(exc).__name__}); the naive agent handled this turn."
        elif req.agent_mode == "llm":
            note = "The LLM agent is unavailable; the naive agent handled this turn."
        if reply is None:
            reply = pack.naive_agent(req.message, cid, call_fn)
        with self._lock:
            state_subject = cid if pack.id == packs_mod.DEFAULT_PACK_ID else (collected[-1].state_after.subject if collected else pack.state_subject(None, {}, cid))
            state = pack.snapshot(self.ledgers[pack.id], state_subject, self.clock(), cid)
            opened = [self.approvals[d.ticket_id] for d in collected if d.outcome == "escalate" and d.ticket_id in self.approvals]
        return ChatResponse(
            reply=reply, agent_mode_used=mode_used, agent_note=note, enforcement=req.enforcement,
            session_customer_id=cid, decisions=collected, state=state, scenario_id=pack.id,
            agent_model=agent_model, approvals=opened,
        )

    # ---------------------------------------------------------------- reset / decisions
    @_locked
    def reset(self, req: ResetRequest) -> ResetResponse:
        scope = req.scope
        targets = [self._pack(req.scenario)] if req.scenario is not None else list(self.packs.values())
        ids = {p.id for p in targets}
        if scope == "all":
            cleared_refunds = 0
            for p in targets:
                led = self.ledgers[p.id]
                cleared_refunds += led.clear()
                led.refund_seq = 0
                led.ticket_seq = 0
            keep = [d for d in self.decisions if d.scenario_id not in ids]
            cleared_decisions = len(self.decisions) - len(keep)
            self.decisions = keep
            gone = [t for t, a in self.approvals.items() if a.scenario_id in ids]
        elif any(scope in p.actors for p in targets):
            cleared_refunds = sum(self.ledgers[p.id].clear(scope) for p in targets)
            keep = [d for d in self.decisions if not (d.session_customer_id == scope and d.scenario_id in ids)]
            cleared_decisions = len(self.decisions) - len(keep)
            self.decisions = keep
            gone = [t for t, a in self.approvals.items() if a.session_customer_id == scope and a.scenario_id in ids]
        else:
            raise ApiError("CUSTOMER_NOT_FOUND", f"Reset scope must be 'all' or a known customer id; got '{scope}'.", 404)
        for t in gone:
            del self.approvals[t]
        now = iso(self.clock())
        self.audit.append(now, "state.reset", f"Demo state reset (scope {scope}): {cleared_decisions} decision(s), {cleared_refunds} ledger entr(ies), {len(gone)} approval(s).",
                          req.scenario, "developer", {"scope": scope, "scenarios": sorted(ids)})
        return ResetResponse(scope=scope, cleared_refunds=cleared_refunds, cleared_decisions=cleared_decisions,
                             reset_at=now, cleared_approvals=len(gone))

    @_locked
    def list_decisions(self, limit: int, scenario_id: Optional[str] = None, outcome: Optional[str] = None) -> DecisionsResponse:
        if scenario_id is not None:
            self._pack(scenario_id)
        newest_first = [d for d in reversed(self.decisions)
                        if (scenario_id is None or d.scenario_id == scenario_id) and (outcome is None or d.outcome == outcome)]
        return DecisionsResponse(decisions=newest_first[:limit], total=len(newest_first), limit=limit)

    # ---------------------------------------------------------------- audit trail
    @_locked
    def audit_events(self, limit: int, scenario_id: Optional[str] = None, type_prefix: Optional[str] = None) -> AuditResponse:
        events = self.audit.newest(limit, scenario_id, type_prefix)
        ok, _ = self.audit.verify()
        total = len(self.audit.newest(10 ** 9, scenario_id, type_prefix))
        return AuditResponse(events=events, total=total, limit=limit, head_hash=self.audit.head_hash, chain_valid=ok)

    @_locked
    def audit_verify(self) -> AuditVerifyResponse:
        ok, broken = self.audit.verify()
        ev = self.audit.events
        return AuditVerifyResponse(chain_valid=ok, events=len(ev), head_hash=self.audit.head_hash,
                                   first_seq=ev[0].seq if ev else None, broken_at_seq=broken, algorithm="sha256")

    @_locked
    def audit_export(self, fmt: str) -> str:
        if fmt == "csv":
            return self.audit.to_csv()
        if fmt == "json":
            return json.dumps({"head_hash": self.audit.head_hash, "algorithm": "sha256",
                               "events": [e.model_dump() for e in self.audit.events]}, ensure_ascii=False, indent=2)
        return self.audit.to_jsonl()

    # ---------------------------------------------------------------- cases
    @_locked
    def cases(self, scenario_id: Optional[str] = None, include_custom: bool = True) -> CasesResponse:
        pack = self._pack(scenario_id)
        builtin = pack.builtin_cases()
        custom = list(self.custom_cases[pack.id]) if include_custom else []
        return CasesResponse(cases=builtin + custom, total=len(builtin) + len(custom), builtin=len(builtin),
                             custom=len(custom), scenario_id=pack.id)

    def _replay(self, pack: Pack, case: CaseSpec, policy: Optional[ApprovedPolicy]) -> Tuple[Any, Any]:
        import runner

        base = self.clock()
        return runner.run_case(case, "off", None, base, pack), (runner.run_case(case, "on", policy, base, pack) if policy else None)

    def _validated_steps(self, pack: Pack, session: str, steps: List[Any]) -> None:
        if session not in pack.actors:
            raise ApiError("CASE_INVALID", f"{pack.actor_label.capitalize()} {session} was not found.", 422)
        for i, step in enumerate(steps):
            err = pack.validate_args(step.tool, step.args)
            if err is None:
                _, err = pack.subject(step.tool, step.args, session)
            if err:
                raise ApiError("CASE_INVALID", f"Step {i + 1}: {err}", 422, {"step": i})

    def _next_case_id(self, pid: str, letter: str) -> str:
        self._case_seq[pid][letter] += 1
        return f"{letter}{self._case_seq[pid][letter]:02d}"

    def add_case(self, req: CaseCreate) -> CaseSpec:
        pack = self._pack(req.scenario)
        session = req.session_customer_id or pack.session_id
        self._validated_steps(pack, session, req.steps)
        harm = req.harm_step
        if req.type == "attack":
            harm = len(req.steps) - 1 if harm is None else harm
            if harm >= len(req.steps):
                raise ApiError("CASE_INVALID", "harm_step must point at one of the steps.", 422)
        else:
            harm = None
        if req.clause_kind is not None and req.clause_kind not in pack.kinds:
            raise ApiError("CASE_INVALID", f"Rule kind '{req.clause_kind}' does not belong to scenario '{pack.id}'.", 422)
        with self._lock:
            if len(self.custom_cases[pack.id]) >= MAX_CUSTOM_CASES:
                raise ApiError("CASE_INVALID", f"At most {MAX_CUSTOM_CASES} custom cases per scenario. Delete some first.", 422)
            policy = self.actives[pack.id]
        probe = CaseSpec(case_id="U00", clause_id="C1", type=req.type, title=req.title, description=req.description,
                         session_customer_id=session, steps=req.steps, harm_step=harm, expected_outcomes=[],
                         scenario_id=pack.id, clause_kind=req.clause_kind, origin="custom")
        expected = req.expected_outcomes
        kind = req.clause_kind
        if expected is not None:
            if len(expected) != len(req.steps):
                raise ApiError("CASE_INVALID", "expected_outcomes needs exactly one outcome per step.", 422)
        elif req.type == "benign":
            expected = ["allow"] * len(req.steps)
        else:
            if policy is None:
                raise no_active_policy(409)
            _, with_ = self._replay(pack, probe, policy)
            expected = list(with_.outcomes)
            if expected[harm] == "allow":
                expected[harm] = "deny"  # an attack's harmful step must never be expected to run: this case will FAIL and show the gap
        if kind is None and policy is not None:
            _, with_ = self._replay(pack, probe, policy)
            hit = next((d.clause_id for d in with_.decisions if d.clause_id), None)
            kind = next((c.kind for c in policy.clauses if c.clause_id == hit), None)
        with self._lock:
            case = probe.model_copy(update={"case_id": self._next_case_id(pack.id, "U"), "clause_kind": kind,
                                            "clause_id": pack.demo_clause_of_kind(kind), "expected_outcomes": expected})
            self.custom_cases[pack.id].append(case)
            self._audit("tests.case_added", f"Custom case {case.case_id} added: {case.title}", pack.id, "developer", {"case_id": case.case_id})
            return case

    @_locked
    def delete_case(self, case_id: str, scenario_id: Optional[str] = None) -> CasesResponse:
        pack = self._pack(scenario_id)
        before = len(self.custom_cases[pack.id])
        self.custom_cases[pack.id] = [c for c in self.custom_cases[pack.id] if c.case_id != case_id]
        if len(self.custom_cases[pack.id]) == before:
            raise ApiError("CASE_NOT_FOUND", f"Custom case {case_id} was not found. Built-in cases cannot be deleted.", 404)
        return self.cases(pack.id)

    @_locked
    def clear_custom_cases(self, scenario_id: Optional[str] = None) -> CasesResponse:
        pack = self._pack(scenario_id)
        self.custom_cases[pack.id] = []
        return self.cases(pack.id)

    def generate_cases(self, req: GenerateRequest) -> GenerateResponse:
        import attackgen

        pack = self._pack(req.scenario)
        with self._lock:
            policy = self.actives[pack.id]
            if policy is None:
                raise no_active_policy(409)
            existing = pack.builtin_cases() + list(self.custom_cases[pack.id])
            cursor = self._gen_cursor[pack.id]
        chain = self._chain(req.provider)
        result = attackgen.generate(pack, policy, existing, req.count, chain, cursor,
                                    lambda case, pol: self._replay(pack, case, pol))
        with self._lock:
            self._gen_cursor[pack.id] = result.cursor
            saved: List[CaseSpec] = []
            for case in result.cases:
                if req.save and len(self.custom_cases[pack.id]) >= MAX_CUSTOM_CASES:
                    result.notes.append(f"The suite is full ({MAX_CUSTOM_CASES} custom cases); the rest were not saved.")
                    break
                case = case.model_copy(update={"case_id": self._next_case_id(pack.id, "G")})
                if req.save:
                    self.custom_cases[pack.id].append(case)
                saved.append(case)
            uncaught = [c.model_copy(update={"case_id": f"X{i + 1:02d}"}) for i, c in enumerate(result.uncaught)]
            self._audit("tests.generated", f"{len(saved)} attack case(s) generated by {result.generated_by}"
                        + (f" ({result.model})" if result.model else "") + f"; {len(uncaught)} got through and need review.",
                        pack.id, "developer", {"generated_by": result.generated_by, "model": result.model,
                                               "case_ids": [c.case_id for c in saved], "uncaught": len(uncaught)})
            return GenerateResponse(scenario_id=pack.id, generated_by=result.generated_by, model=result.model, cases=saved,
                                    uncaught=uncaught, rejected=result.rejected, notes=result.notes)

    # ---------------------------------------------------------------- test runs + reports
    def run_tests(self, req: RunTestsRequest) -> TestReport:
        import runner  # local import: runner imports this module

        pack = self._pack(req.scenario)
        with self._lock:
            policy = self.actives[pack.id]
            if policy is None:
                raise no_active_policy(409)
            if req.policy_id is not None and req.policy_id != policy.policy_id:
                raise ApiError("POLICY_NOT_ACTIVE", f"Policy {req.policy_id} is not the active policy ({policy.policy_id}). Approve it first.", 409)
            self._report_seq += 1
            report_id = f"rep_{self._report_seq:04d}"
            cases = pack.builtin_cases() + (list(self.custom_cases[pack.id]) if req.include_custom else [])
        report = runner.run_suite(policy, report_id, self.clock(), pack, cases)  # isolated ledgers; never touches live state
        self._store_report(report, pack.id, latest=True)
        self._audit("tests.run", f"Report {report_id}: {report.metrics.cases_matching_expected}/{report.case_count} cases as expected "
                    f"({'PASS' if report.passed else 'FAIL'}) on policy v{policy.policy_version}.", pack.id, "developer",
                    {"report_id": report_id, "passed": report.passed, "policy_version": policy.policy_version,
                     "failed_case_ids": report.failed_case_ids})
        return report

    def _store_report(self, report: TestReport, pid: str, latest: bool) -> None:
        with self._lock:
            self.reports[report.report_id] = report
            if latest:
                self.latest_report_id = report.report_id
                self.latest_report_ids[pid] = report.report_id
            if len(self.reports) > MAX_REPORTS:
                keep = set(self.latest_report_ids.values())
                for key in list(self.reports):
                    if len(self.reports) <= MAX_REPORTS:
                        break
                    if key not in keep:
                        del self.reports[key]

    @_locked
    def latest_report(self, scenario_id: Optional[str] = None) -> TestReport:
        rid = self.latest_report_id if scenario_id is None else self.latest_report_ids[self._pack(scenario_id).id]
        if rid is None:
            raise ApiError("NO_REPORT", "No tests have been run yet. Run the tests first.", 404)
        return self.reports[rid]

    @_locked
    def get_report(self, report_id: str) -> TestReport:
        if report_id == "latest":
            return self.latest_report()
        rep = self.reports.get(report_id)
        if rep is None:
            raise ApiError("REPORT_NOT_FOUND", f"Report {report_id} was not found.", 404)
        return rep

    def run_ci(self, req: CiRunRequest) -> CiRunResponse:
        """pytest for a policy file: compile, answer, run, and say pass or fail. Stateless: the live policy is untouched."""
        import exports
        import runner

        pack = self._pack(req.scenario)
        text = req.policy_text.strip()
        warnings: List[str] = []
        if req.clauses is not None:
            sentences = {_norm(s) for s in compiler_mod.split_sentences(text)}
            for c in req.clauses:
                if _norm(c.source_sentence) not in sentences:
                    raise ApiError("IMPORT_INVALID", f"Rule {c.clause_id} cites a sentence that is not in the policy text.", 422, {"clause_id": c.clause_id})
            try:
                compiled = compiler_mod.finalize([(c.source_sentence, c.kind, c.params.model_dump()) for c in req.clauses], [], [], pack)
            except compiler_mod.CompileError as exc:
                raise ApiError("IMPORT_INVALID", str(exc), 422) from exc
            compiled_by = "import"
            clauses, answers = compiled.clauses, []  # a lock file is already resolved: test exactly what was committed
        else:
            compiled, compiled_by, _, warnings = self._compile_text(text, pack, req.provider)
            given = self._check_answers(compiled.ambiguities, req.answers)
            full = {a.ambiguity_id: given.get(a.ambiguity_id, a.default_option_id) for a in compiled.ambiguities}
            defaulted = [a.ambiguity_id for a in compiled.ambiguities if a.ambiguity_id not in given]
            if defaulted:
                warnings.append(f"{len(defaulted)} open question(s) took their default answer ({', '.join(defaulted)}). Commit the clause file to pin them.")
            clauses = compiler_mod.apply_answers(compiled.clauses, compiled.ambiguities, full, compiled.patches)
            answers = [AmbiguityAnswer(ambiguity_id=k, option_id=full[k]) for k in sorted(full)]
        warnings = list(compiled.warnings) + warnings
        with self._lock:
            self._ci_seq += 1
            report_id = f"ci_{self._ci_seq:04d}"
            cases = pack.builtin_cases() + (list(self.custom_cases[pack.id]) if req.include_custom else [])
        policy = ApprovedPolicy(policy_id=report_id, policy_version=0, approved_at=iso(self.clock()), policy_text=text,
                                compiled_by=compiled_by, clauses=clauses, answers=answers, diff=[], scenario_id=pack.id,
                                approved_by="ci", note="Ephemeral CI policy; never activated.")
        report = runner.run_suite(policy, report_id, self.clock(), pack, cases)
        self._store_report(report, pack.id, latest=False)
        m = report.metrics
        summary = (f"{'PASS' if report.passed else 'FAIL'}: {m.cases_matching_expected}/{report.case_count} cases as expected, "
                   f"{m.attacks_succeeded_with_firewall}/{m.attack_cases} attacks executed with the firewall, "
                   f"{m.benign_passed_with_firewall}/{m.benign_cases} legitimate cases allowed.")
        self._audit("ci.run", f"{report_id}: {summary}", pack.id, "ci", {"report_id": report_id, "passed": report.passed})
        return CiRunResponse(passed=report.passed, exit_code=report.exit_code, summary=summary, report=report, clauses=clauses,
                             answers=answers, warnings=warnings, junit_xml=exports.junit_xml(report), markdown=exports.markdown_summary(report))

    # ---------------------------------------------------------------- compile benchmark
    def start_bench(self, req: BenchRequest) -> BenchStatus:
        import bench_compile

        with self._lock:
            if self.bench is not None and self.bench.status == "running":
                raise ApiError("BENCH_RUNNING", "A benchmark is already running. Poll GET /bench/compile/latest.", 409)
            self._bench_seq += 1
            corpus = bench_compile.CORPUS[: req.limit]
            chain = self._chain(req.provider)
            self.bench = BenchStatus(
                bench_id=f"bench_{self._bench_seq:03d}", status="running", requested_provider=req.provider,
                model=chain[0].model if chain else None, total=len(corpus), completed=0, exact_matches=0, clause_matches=0,
                clause_total=0, exact_match_rate=0.0, clause_match_rate=0.0, fell_back=0, median_latency_ms=0.0,
                started_at=iso(self.clock()), finished_at=None, items=[], note=bench_compile.NOTE,
            )
            status = self.bench

        def work() -> None:
            items: List[BenchItem] = []
            try:
                for entry in corpus:
                    items.append(bench_compile.run_item(self, entry, req.provider))
                    self._bench_update(status.bench_id, items, done=False)
                self._bench_update(status.bench_id, items, done=True)
            except Exception as exc:  # noqa: BLE001
                log.exception("benchmark failed")
                with self._lock:
                    if self.bench and self.bench.bench_id == status.bench_id:
                        self.bench = self.bench.model_copy(update={"status": "failed", "finished_at": iso(self.clock()),
                                                                   "note": f"Benchmark stopped: {type(exc).__name__}."})

        threading.Thread(target=work, name="polyx-bench", daemon=True).start()
        return status

    def _bench_update(self, bench_id: str, items: List[BenchItem], done: bool) -> None:
        with self._lock:
            if self.bench is None or self.bench.bench_id != bench_id:
                return
            clause_total = sum(i.expected_clauses for i in items)
            clause_matches = sum(i.matched_clauses for i in items)
            exact = sum(i.exact for i in items)
            requested_model = self.bench.requested_provider in ("auto", "local", "cloud") and self.bench.model is not None
            self.bench = self.bench.model_copy(update={
                "status": "done" if done else "running", "completed": len(items), "items": list(items),
                "exact_matches": exact, "clause_matches": clause_matches, "clause_total": clause_total,
                "exact_match_rate": round(exact / len(items), 4) if items else 0.0,
                "clause_match_rate": round(clause_matches / clause_total, 4) if clause_total else 0.0,
                "fell_back": sum(1 for i in items if requested_model and i.provider == "rules"),
                "median_latency_ms": round(statistics.median(i.latency_ms for i in items), 1) if items else 0.0,
                "finished_at": iso(self.clock()) if done else None,
            })
            if done:
                self.audit.append(iso(self.clock()), "bench.compile", f"Compile benchmark {bench_id}: {exact}/{len(items)} policies matched the reference exactly.",
                                  None, "developer", {"bench_id": bench_id, "exact": exact, "total": len(items), "model": self.bench.model})

    @_locked
    def latest_bench(self) -> BenchStatus:
        if self.bench is None:
            raise ApiError("NO_BENCH", "No compile benchmark has been run yet. POST /bench/compile first.", 404)
        return self.bench


__all__ = ["Engine", "Ledger", "Verdict", "Violation", "evaluate", "run_call", "diff_policies", "iso", "utcnow",
           "next_decision_id", "bundle_checksum"]
