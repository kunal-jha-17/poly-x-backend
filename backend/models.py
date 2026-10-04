"""POLY-X contract v1.1.0 - the single source of truth for every JSON shape.

Rules:
  * snake_case keys, money is a whole-number rupee integer named amount_inr
  * timestamps are ISO-8601 UTC strings (produced by engine.iso)
  * unknown / extra fields are rejected (extra="forbid")
  * types/api.d.ts is generated from this file (generate_types.py) and a test enforces the match

v1.1.0 is ADDITIVE over v1.0.0: every v1.0.0 field keeps its name, type and meaning, so a v1.0.0 client
keeps working. New in 1.1.0: scenario packs (support + devops), swappable model providers, the guard API,
the approval inbox, custom / generated test cases, CI exports, policy-as-code and the audit trail.

Change process: edit this file + types/api.d.ts together (python generate_types.py), regenerate fixtures,
bump CONTRACT_VERSION. Never patch one side.
"""
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

CONTRACT_VERSION = "1.1.0"
WINDOW_HOURS = 24  # window used by the informational state snapshot (rolling 24h)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- enums
Outcome = Literal["allow", "deny", "escalate"]
Enforcement = Literal["on", "off"]
AgentModeRequest = Literal["auto", "naive", "llm"]
AgentModeUsed = Literal["naive", "llm"]
CompiledBy = Literal["llm", "fixture", "import"]
CompileMode = Literal["auto", "fixture"]
ProviderChoice = Literal["auto", "local", "cloud", "fixture"]
CompilerProvider = Literal["local", "cloud", "device", "rules", "import"]
ModelLocation = Literal["local", "cloud", "on_device", "server"]
PolicySource = Literal["typed", "voice", "ocr", "share", "file"]
ClauseKind = Literal[
    "per_txn_limit", "cumulative_limit", "data_scope", "precondition",  # support pack
    "env_approval", "deploy_rate_limit", "secret_protection", "command_block",  # devops pack
]
ClauseAction = Literal["deny", "escalate"]
CaseType = Literal["attack", "benign"]
CaseOrigin = Literal["builtin", "custom", "generated"]
OrderStatus = Literal["delivered", "shipped", "processing"]
Environment = Literal["dev", "staging", "production"]
DiffChange = Literal["added", "changed", "removed", "unchanged"]
ToolName = Literal[
    "lookup_order", "issue_refund", "fetch_customer_data",  # support pack
    "run_shell", "deploy", "read_secret",  # devops pack
]
ApprovalStatus = Literal["pending", "approved", "rejected"]
ApprovalAction = Literal["approve", "reject"]
StateUnit = Literal["inr", "deploys"]

ErrorCode = Literal[
    "VALIDATION_ERROR",
    "COMPILE_FAILED",
    "AMBIGUITY_UNRESOLVED",
    "POLICY_NOT_FOUND",
    "REPORT_NOT_FOUND",
    "CUSTOMER_NOT_FOUND",
    "NO_ACTIVE_POLICY",
    "POLICY_ALREADY_APPROVED",
    "POLICY_NOT_ACTIVE",
    "NO_REPORT",
    "NETWORK_ERROR",  # client-created
    "BAD_JSON",  # client-created
    "NOT_FOUND",  # unknown route
    "METHOD_NOT_ALLOWED",  # wrong verb
    "INTERNAL_ERROR",  # unexpected failure, contract-shaped
    # ---- added in 1.1.0
    "SCENARIO_NOT_FOUND",
    "APPROVAL_NOT_FOUND",
    "APPROVAL_ALREADY_RESOLVED",
    "CASE_NOT_FOUND",
    "CASE_INVALID",
    "VERSION_NOT_FOUND",
    "IMPORT_INVALID",
    "MODEL_UNAVAILABLE",
    "ADMIN_REQUIRED",
    "RATE_LIMITED",
    "PAYLOAD_TOO_LARGE",
    "BENCH_RUNNING",
    "NO_BENCH",
]

# Fixed by kind: the engine, not the LLM, decides what a violated clause does.
KIND_ACTION: Dict[str, str] = {
    "per_txn_limit": "escalate",
    "cumulative_limit": "deny",
    "data_scope": "deny",
    "precondition": "deny",
    "env_approval": "escalate",
    "deploy_rate_limit": "deny",
    "secret_protection": "deny",
    "command_block": "deny",
}


# ---------------------------------------------------------------- errors
class ErrorBody(Strict):
    code: ErrorCode
    message: str
    details: Optional[Dict[str, Any]]


class ErrorEnvelope(Strict):
    error: ErrorBody


# ---------------------------------------------------------------- clause params (per kind)
class PerTxnParams(Strict):
    field: Literal["amount_inr"]
    operator: Literal["gt"]
    value: StrictInt = Field(ge=0, le=1_000_000_000)
    scope: Literal["transaction", "customer_24h"]


class CumulativeParams(Strict):
    field: Literal["amount_inr"]
    max_total: StrictInt = Field(ge=0, le=1_000_000_000)
    window_hours: StrictInt = Field(ge=1, le=720)
    window_type: Literal["rolling", "calendar_day"]
    scope: Literal["customer"]


class DataScopeParams(Strict):
    subject: Literal["session_customer"]


class PreconditionParams(Strict):
    field: Literal["order.status"]
    operator: Literal["eq"]
    value: OrderStatus


class EnvApprovalParams(Strict):
    """devops: a deploy to one of these environments is held for a human."""
    field: Literal["environment"]
    operator: Literal["in"]
    environments: List[Environment] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def _unique(self) -> "EnvApprovalParams":
        if len(set(self.environments)) != len(self.environments):
            raise ValueError("environments must not repeat")
        return self


class DeployRateParams(Strict):
    """devops: at most max_count executed deploys per environment per window."""
    field: Literal["deploy_count"]
    max_count: StrictInt = Field(ge=0, le=10_000)
    window_hours: StrictInt = Field(ge=1, le=720)
    window_type: Literal["rolling", "calendar_day"]
    scope: Literal["environment"]


class SecretProtectionParams(Strict):
    """devops: secret values never reach the agent (read_secret, or a shell command that dumps them)."""
    subject: Literal["secret_values"]


class CommandBlockParams(Strict):
    """devops: destructive shell commands never run. allowlist mode only permits known read-only commands."""
    category: Literal["destructive"]
    mode: Literal["denylist", "allowlist"]


ClauseParams = Union[
    PerTxnParams, CumulativeParams, DataScopeParams, PreconditionParams,
    EnvApprovalParams, DeployRateParams, SecretProtectionParams, CommandBlockParams,
]
KIND_PARAMS = {
    "per_txn_limit": PerTxnParams,
    "cumulative_limit": CumulativeParams,
    "data_scope": DataScopeParams,
    "precondition": PreconditionParams,
    "env_approval": EnvApprovalParams,
    "deploy_rate_limit": DeployRateParams,
    "secret_protection": SecretProtectionParams,
    "command_block": CommandBlockParams,
}


class Clause(Strict):
    clause_id: str = Field(pattern=r"^C[1-9][0-9]{0,2}$")
    source_sentence: str = Field(min_length=1, max_length=500)
    kind: ClauseKind
    action: ClauseAction
    params: ClauseParams

    @model_validator(mode="after")
    def _kind_matches_params_and_action(self) -> "Clause":
        if not isinstance(self.params, KIND_PARAMS[self.kind]):
            raise ValueError(f"params do not match kind '{self.kind}'")
        if self.action != KIND_ACTION[self.kind]:
            raise ValueError(f"kind '{self.kind}' always has action '{KIND_ACTION[self.kind]}'")
        return self


# ---------------------------------------------------------------- state + decision
class RefundState(Strict):
    """Ledger snapshot for the subject a rule counts against.

    v1.0.0 fields keep their meaning for the support pack. `subject`, `unit`, `total` and `count` are the
    scenario-neutral view: support counts rupees refunded per customer, devops counts deploys per environment.
    """
    customer_id: str
    refund_total_24h_inr: int
    refund_count_24h: int
    window_hours: int
    subject: str = ""
    unit: StateUnit = "inr"
    total: int = 0
    count: int = 0


class Decision(Strict):
    decision_id: str
    timestamp: str
    tool: str
    args: Dict[str, Any]
    session_customer_id: str
    enforced: bool
    outcome: Outcome
    executed: bool
    clause_id: Optional[str]
    source_sentence: Optional[str]
    reason: str
    policy_version: Optional[int]
    state_before: RefundState
    state_after: RefundState
    latency_ms: float
    tool_result: Optional[Dict[str, Any]]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    ticket_id: Optional[str] = None  # set when the call was held for a human (escalate) or released by one
    approved_by: Optional[str] = None  # set when a human released a held call from the approval inbox
    dry_run: bool = False  # guard API evaluate-only: nothing was executed or recorded


# ---------------------------------------------------------------- models / providers
class ModelInfo(Strict):
    provider: Literal["local", "cloud", "rules"]
    label: str
    model: Optional[str]
    host: Optional[str]  # host name only; never a key or a full URL with credentials
    location: ModelLocation
    configured: bool
    available: bool
    last_checked_at: Optional[str]
    last_error: Optional[str]
    latency_ms: Optional[float]


class ModelsResponse(Strict):
    providers: List[ModelInfo]
    order: List[str]  # the order `auto` tries providers in; the rule parser is always the last resort
    runtime_config_enabled: bool  # true when PUT /models/local is usable (an admin token is set)


class LocalModelConfig(Strict):
    base_url: str = Field(min_length=8, max_length=300)
    model: str = Field(min_length=1, max_length=120)
    api_key: Optional[str] = Field(default=None, max_length=300)


class CompileAttempt(Strict):
    provider: CompilerProvider
    model: Optional[str]
    ok: bool
    latency_ms: float
    error: Optional[str]


class CompilerInfo(Strict):
    """Who proposed the clauses. The engine that decides is always deterministic code."""
    provider: CompilerProvider
    model: Optional[str]
    location: ModelLocation
    label: str
    latency_ms: float
    attempts: List[CompileAttempt]


class ValidationCheck(Strict):
    check: str
    passed: bool
    detail: str


# ---------------------------------------------------------------- health + scenario
class ScenarioStatus(Strict):
    scenario_id: str
    title: str
    active_policy_version: Optional[int]


class Health(Strict):
    status: Literal["ok"]
    contract_version: str
    llm_available: bool
    active_policy_version: Optional[int]  # support pack (v1.0.0 meaning)
    # ---- added in 1.1.0
    service: str = "poly-x"
    uptime_s: float = 0.0
    scenarios: List[ScenarioStatus] = []
    models: List[ModelInfo] = []
    pending_approvals: int = 0
    auto_armed: bool = False


class ToolSpec(Strict):
    name: ToolName
    description: str
    params: Dict[str, str]


class Customer(Strict):
    customer_id: str
    name: str
    email: Optional[str] = None  # reserved example.com addresses only
    role: Optional[str] = None


class Order(Strict):
    order_id: str
    customer_id: str
    status: OrderStatus
    amount_inr: int
    item: str
    note: Optional[str]


class Resource(Strict):
    """Scenario-neutral thing the tools act on (devops: services, environments, secrets, files)."""
    resource_id: str
    kind: str
    name: str
    detail: Optional[str]


class AttackPreset(Strict):
    preset_id: str
    title: str
    description: str
    clause_id: str
    message: str
    repeat: int


class Scenario(Strict):
    session_customer_id: str
    default_policy_text: str
    tools: List[ToolSpec]
    customers: List[Customer]
    orders: List[Order]
    attack_presets: List[AttackPreset]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    title: str = ""
    description: str = ""
    actor_label: str = "customer"
    resources: List[Resource] = []
    safe_presets: List[AttackPreset] = []
    clause_kinds: List[ClauseKind] = []
    supported_rules: str = ""


class ScenarioSummary(Strict):
    scenario_id: str
    title: str
    description: str
    actor_label: str
    tools: List[str]
    clause_kinds: List[ClauseKind]
    active_policy_version: Optional[int]
    builtin_cases: int
    custom_cases: int


class ScenariosResponse(Strict):
    scenarios: List[ScenarioSummary]
    default_scenario_id: str


# ---------------------------------------------------------------- policy compile / approve
class CompileRequest(Strict):
    policy_text: str = Field(min_length=1, max_length=5000)
    mode: CompileMode = "auto"
    # ---- added in 1.1.0
    scenario: str = "support"
    provider: Optional[ProviderChoice] = None  # None = follow `mode`
    source: PolicySource = "typed"  # "ocr" re-joins lines that a camera scan wrapped
    proposal: Optional[Dict[str, Any]] = None  # raw JSON proposed by an on-device model; goes through the same gate
    proposal_model: Optional[str] = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def _not_blank(self) -> "CompileRequest":
        if not self.policy_text.strip():
            raise ValueError("policy_text must not be blank")
        return self


class AmbiguityOption(Strict):
    option_id: str
    label: str
    description: str


class Ambiguity(Strict):
    ambiguity_id: str
    clause_id: str
    question: str
    options: List[AmbiguityOption]
    default_option_id: str


class PolicyDraft(Strict):
    policy_id: str
    created_at: str
    policy_text: str
    compiled_by: CompiledBy
    clauses: List[Clause]
    ambiguities: List[Ambiguity]
    warnings: List[str]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    compiler: Optional[CompilerInfo] = None
    validation: List[ValidationCheck] = []
    source: PolicySource = "typed"


class AmbiguityAnswer(Strict):
    ambiguity_id: str
    option_id: str


class ApproveRequest(Strict):
    answers: List[AmbiguityAnswer] = []
    approved_by: Optional[str] = Field(default=None, max_length=80)


class DiffRow(Strict):
    clause_id: str
    change: DiffChange
    source_sentence: str
    detail: Optional[str]


class ApprovedPolicy(Strict):
    policy_id: str
    policy_version: int
    approved_at: str
    policy_text: str
    compiled_by: CompiledBy
    clauses: List[Clause]
    answers: List[AmbiguityAnswer]
    diff: List[DiffRow]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    compiler: Optional[CompilerInfo] = None
    approved_by: str = "reviewer"
    note: Optional[str] = None


class PromptResponse(Strict):
    """The exact prompt the server gives its own model, so an on-device model can propose with the same one."""
    scenario_id: str
    system_prompt: str
    user_template: str  # contains the literal marker {policy_text}
    clause_kinds: List[ClauseKind]


class PolicyHistoryResponse(Strict):
    scenario_id: str
    versions: List[ApprovedPolicy]  # newest first
    active_policy_version: Optional[int]


class TextDiffLine(Strict):
    op: Literal["same", "add", "remove"]
    text: str


class PolicyDiffResponse(Strict):
    scenario_id: str
    from_version: int
    to_version: int
    clause_diff: List[DiffRow]
    text_diff: List[TextDiffLine]
    unified: str  # ready to paste into a review


class PolicyBundle(Strict):
    """policy-as-code file: commit it next to your agent. policy_text is your policy.md, clauses is the lock file."""
    format: Literal["polyx.policy/v1"]
    scenario_id: str
    policy_version: Optional[int] = None
    policy_text: str = Field(min_length=1, max_length=5000)
    clauses: List[Clause] = Field(min_length=1, max_length=50)
    compiled_by: Optional[CompiledBy] = None
    exported_at: Optional[str] = None
    checksum: Optional[str] = None  # sha256 over scenario_id + policy_text + clauses


class RollbackRequest(Strict):
    scenario: str = "support"
    version: int = Field(ge=1)
    approved_by: Optional[str] = Field(default=None, max_length=80)


# ---------------------------------------------------------------- approval inbox
class Approval(Strict):
    ticket_id: str
    scenario_id: str
    status: ApprovalStatus
    created_at: str
    decision_id: str
    tool: str
    args: Dict[str, Any]
    session_customer_id: str
    summary: str  # one plain sentence a human can approve from a phone lock screen
    clause_id: Optional[str]
    source_sentence: Optional[str]
    reason: str
    policy_version: Optional[int]
    resolved_at: Optional[str]
    resolved_by: Optional[str]
    note: Optional[str]
    result_decision_id: Optional[str]
    result_outcome: Optional[Outcome]
    result_reason: Optional[str]


class ApprovalsResponse(Strict):
    approvals: List[Approval]  # newest first
    pending: int
    total: int


class ResolveRequest(Strict):
    action: ApprovalAction
    approver: str = Field(default="reviewer", min_length=1, max_length=80)
    note: Optional[str] = Field(default=None, max_length=300)


class ApprovalResolution(Strict):
    approval: Approval
    decision: Optional[Decision]  # the released call (approve) - still checked against every deny rule


# ---------------------------------------------------------------- live agent
class ChatRequest(Strict):
    message: str = Field(min_length=1, max_length=2000)
    session_customer_id: Optional[str] = None  # default: the scenario's session actor (support: C-1001)
    enforcement: Enforcement = "on"
    agent_mode: AgentModeRequest = "auto"
    # ---- added in 1.1.0
    scenario: str = "support"
    provider: Optional[ProviderChoice] = None

    @model_validator(mode="after")
    def _not_blank(self) -> "ChatRequest":
        if not self.message.strip():
            raise ValueError("message must not be blank")
        return self


class ChatResponse(Strict):
    reply: str
    agent_mode_used: AgentModeUsed
    agent_note: Optional[str]
    enforcement: Enforcement
    session_customer_id: str
    decisions: List[Decision]
    state: RefundState
    # ---- added in 1.1.0
    scenario_id: str = "support"
    agent_model: Optional[str] = None
    approvals: List[Approval] = []  # tickets opened by this turn


class GuardRequest(Strict):
    """The product: call this before your agent runs a tool."""
    tool: str = Field(min_length=1, max_length=64)
    args: Dict[str, Any] = {}
    scenario: str = "support"
    session_customer_id: Optional[str] = None
    dry_run: bool = False  # true = evaluate only; nothing is executed, recorded or held


class GuardResponse(Strict):
    allowed: bool
    outcome: Outcome
    executed: bool
    clause_id: Optional[str]
    source_sentence: Optional[str]
    reason: str
    ticket_id: Optional[str]
    policy_version: Optional[int]
    latency_ms: float
    dry_run: bool
    decision: Decision


class ResetRequest(Strict):
    scope: str = "all"
    scenario: Optional[str] = None  # None = every scenario


class ResetResponse(Strict):
    scope: str
    cleared_refunds: int
    cleared_decisions: int
    reset_at: str
    cleared_approvals: int = 0


class DecisionsResponse(Strict):
    decisions: List[Decision]
    total: int
    limit: int


# ---------------------------------------------------------------- cases + report
class CaseStep(Strict):
    tool: str = Field(min_length=1, max_length=64)
    args: Dict[str, Any]
    at_offset_hours: float = Field(default=0.0, ge=0.0, le=720.0)


class CaseSpec(Strict):
    case_id: str
    clause_id: str
    type: CaseType
    title: str
    description: str
    session_customer_id: str
    steps: List[CaseStep]
    harm_step: Optional[int]
    expected_outcomes: List[Outcome]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    clause_kind: Optional[ClauseKind] = None
    origin: CaseOrigin = "builtin"
    generated_by: Optional[str] = None


class CasesResponse(Strict):
    cases: List[CaseSpec]
    total: int
    builtin: int = 0
    custom: int = 0
    scenario_id: str = "support"


class CaseCreate(Strict):
    scenario: str = "support"
    type: CaseType
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=400)
    session_customer_id: Optional[str] = None
    clause_kind: Optional[ClauseKind] = None
    steps: List[CaseStep] = Field(min_length=1, max_length=8)
    harm_step: Optional[int] = Field(default=None, ge=0, le=7)
    expected_outcomes: Optional[List[Outcome]] = None  # omitted = recorded from the active policy (attack harm step must not be allow)


class GenerateRequest(Strict):
    scenario: str = "support"
    count: int = Field(default=5, ge=1, le=10)
    provider: Optional[ProviderChoice] = None  # fixture = deterministic mutation engine, no model
    save: bool = True


class GenerateResponse(Strict):
    scenario_id: str
    generated_by: Literal["llm", "mutation"]
    model: Optional[str]
    cases: List[CaseSpec]  # validated, replayed against the active policy, and (if save) added to the suite
    uncaught: List[CaseSpec]  # proposed attacks the active policy ALLOWED: a gap to review, never auto-added
    rejected: int  # proposals dropped by the schema / replay gate
    notes: List[str]


class RunTestsRequest(Strict):
    policy_id: Optional[str] = None
    scenario: str = "support"
    include_custom: bool = True


class RunResult(Strict):
    outcomes: List[Outcome]
    harmful_action_executed: bool
    all_allowed: bool
    decisions: List[Decision]


class CaseResult(Strict):
    case_id: str
    clause_id: Optional[str]
    type: CaseType
    title: str
    expected_outcomes: List[Outcome]
    matches_expected: bool
    without_firewall: RunResult
    with_firewall: RunResult
    # ---- added in 1.1.0
    description: str = ""
    origin: CaseOrigin = "builtin"
    clause_kind: Optional[ClauseKind] = None


class ClauseCoverage(Strict):
    clause_id: str
    source_sentence: str
    attack_case_ids: List[str]
    benign_case_ids: List[str]
    covered: bool


class LatencySummary(Strict):
    scope: Literal["in_process_rule_evaluation"]
    samples: int
    mean_ms: float
    median_ms: float
    p95_ms: float
    max_ms: float


class Metrics(Strict):
    attack_cases: int
    attacks_succeeded_without_firewall: int
    attacks_succeeded_with_firewall: int
    attack_success_rate_without_firewall: float
    attack_success_rate_with_firewall: float
    benign_cases: int
    benign_passed_with_firewall: int
    benign_pass_rate_with_firewall: float
    cumulative_attack_cases: int
    cumulative_attacks_caught: int
    clauses_total: int
    clauses_with_attack_tests: int
    cases_matching_expected: int


class TestReport(Strict):
    __test__ = False  # not a pytest class

    report_id: str
    created_at: str
    policy_id: str
    policy_version: int
    compiled_by: CompiledBy
    case_count: int
    metrics: Metrics
    coverage: List[ClauseCoverage]
    latency: LatencySummary
    cases: List[CaseResult]
    limitations: List[str]
    # ---- added in 1.1.0
    scenario_id: str = "support"
    passed: bool = True  # every case matched its expected outcomes and no attack executed
    exit_code: int = 0  # 0 pass, 1 fail - what a CI job should exit with
    builtin_case_count: int = 0
    custom_case_count: int = 0
    failed_case_ids: List[str] = []


class CiRunRequest(Strict):
    """One-shot, stateless: compile -> answer ambiguities -> run the suite. Never touches the live policy."""
    policy_text: str = Field(min_length=1, max_length=5000)
    scenario: str = "support"
    provider: ProviderChoice = "fixture"  # deterministic by default, so CI is repeatable
    answers: List[AmbiguityAnswer] = []  # unanswered ambiguities take their default option
    clauses: Optional[List[Clause]] = None  # a committed clause lock file: skip compile, test exactly these
    include_custom: bool = False

    @model_validator(mode="after")
    def _not_blank(self) -> "CiRunRequest":
        if not self.policy_text.strip():
            raise ValueError("policy_text must not be blank")
        return self


class CiRunResponse(Strict):
    passed: bool
    exit_code: int
    summary: str
    report: TestReport
    clauses: List[Clause]
    answers: List[AmbiguityAnswer]
    warnings: List[str]
    junit_xml: str
    markdown: str


# ---------------------------------------------------------------- audit trail
class AuditEvent(Strict):
    seq: int
    timestamp: str
    type: str
    scenario_id: Optional[str]
    actor: str
    summary: str
    data: Dict[str, Any]
    prev_hash: str
    hash: str


class AuditResponse(Strict):
    events: List[AuditEvent]  # newest first
    total: int
    limit: int
    head_hash: str
    chain_valid: bool


class AuditVerifyResponse(Strict):
    chain_valid: bool
    events: int
    head_hash: str
    first_seq: Optional[int]
    broken_at_seq: Optional[int]
    algorithm: Literal["sha256"]


# ---------------------------------------------------------------- compile benchmark
class BenchRequest(Strict):
    provider: ProviderChoice = "auto"
    limit: int = Field(default=16, ge=1, le=16)


class BenchItem(Strict):
    item_id: str
    scenario_id: str
    policy_text: str
    expected_clauses: int
    matched_clauses: int
    exact: bool
    compiled_by: Optional[CompiledBy]
    provider: Optional[CompilerProvider]
    latency_ms: float
    error: Optional[str]


class BenchStatus(Strict):
    bench_id: str
    status: Literal["running", "done", "failed"]
    requested_provider: ProviderChoice
    model: Optional[str]
    total: int
    completed: int
    exact_matches: int  # policies whose every clause (kind + params) equals the hand-written reference
    clause_matches: int
    clause_total: int
    exact_match_rate: float
    clause_match_rate: float
    fell_back: int  # policies where the requested model failed the gate and the rule parser answered instead
    median_latency_ms: float
    started_at: str
    finished_at: Optional[str]
    items: List[BenchItem]
    note: str


# Order matters: dependencies first. generate_types.py emits interfaces in this order.
ALL_MODELS = [
    ErrorBody, ErrorEnvelope,
    PerTxnParams, CumulativeParams, DataScopeParams, PreconditionParams,
    EnvApprovalParams, DeployRateParams, SecretProtectionParams, CommandBlockParams, Clause,
    RefundState, Decision,
    ModelInfo, ModelsResponse, LocalModelConfig, CompileAttempt, CompilerInfo, ValidationCheck,
    ScenarioStatus, Health, ToolSpec, Customer, Order, Resource, AttackPreset, Scenario,
    ScenarioSummary, ScenariosResponse,
    CompileRequest, AmbiguityOption, Ambiguity, PolicyDraft, AmbiguityAnswer, ApproveRequest,
    DiffRow, ApprovedPolicy, PromptResponse, PolicyHistoryResponse, TextDiffLine, PolicyDiffResponse,
    PolicyBundle, RollbackRequest,
    Approval, ApprovalsResponse, ResolveRequest, ApprovalResolution,
    ChatRequest, ChatResponse, GuardRequest, GuardResponse, ResetRequest, ResetResponse, DecisionsResponse,
    CaseStep, CaseSpec, CasesResponse, CaseCreate, GenerateRequest, GenerateResponse,
    RunTestsRequest, RunResult, CaseResult,
    ClauseCoverage, LatencySummary, Metrics, TestReport, CiRunRequest, CiRunResponse,
    AuditEvent, AuditResponse, AuditVerifyResponse,
    BenchRequest, BenchItem, BenchStatus,
]

# Named literal aliases that also appear as TS type aliases.
TS_ALIASES = {
    "Outcome": Outcome, "Enforcement": Enforcement, "AgentModeRequest": AgentModeRequest,
    "AgentModeUsed": AgentModeUsed, "CompiledBy": CompiledBy, "CompileMode": CompileMode,
    "ProviderChoice": ProviderChoice, "CompilerProvider": CompilerProvider, "ModelLocation": ModelLocation,
    "PolicySource": PolicySource,
    "ClauseKind": ClauseKind, "ClauseAction": ClauseAction, "CaseType": CaseType, "CaseOrigin": CaseOrigin,
    "OrderStatus": OrderStatus, "Environment": Environment, "DiffChange": DiffChange, "ToolName": ToolName,
    "ApprovalStatus": ApprovalStatus, "ApprovalAction": ApprovalAction, "StateUnit": StateUnit,
    "ErrorCode": ErrorCode,
}
