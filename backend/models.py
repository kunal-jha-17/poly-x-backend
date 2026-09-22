"""CryptiX contract v1.0.0 - the single source of truth for every JSON shape.

Rules (Part A of the backend brief):
  * snake_case keys, money is a whole-number rupee integer named amount_inr
  * timestamps are ISO-8601 UTC strings (produced by engine.iso)
  * unknown / extra fields are rejected (extra="forbid")
  * types/api.d.ts is generated from this file (generate_types.py) and a test enforces the match

Change process is Part C4: edit this file + types/api.d.ts together, regenerate fixtures,
bump CONTRACT_VERSION, tell Gaurav. Never patch one side.
"""
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

CONTRACT_VERSION = "1.0.0"
WINDOW_HOURS = 24  # window used by the informational state snapshot (rolling 24h)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- enums
Outcome = Literal["allow", "deny", "escalate"]
Enforcement = Literal["on", "off"]
AgentModeRequest = Literal["auto", "naive", "llm"]
AgentModeUsed = Literal["naive", "llm"]
CompiledBy = Literal["llm", "fixture"]
CompileMode = Literal["auto", "fixture"]
ClauseKind = Literal["per_txn_limit", "cumulative_limit", "data_scope", "precondition"]
ClauseAction = Literal["deny", "escalate"]
CaseType = Literal["attack", "benign"]
OrderStatus = Literal["delivered", "shipped", "processing"]
DiffChange = Literal["added", "changed", "removed", "unchanged"]
ToolName = Literal["lookup_order", "issue_refund", "fetch_customer_data"]

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
    "NOT_FOUND",  # unknown route (server safety net, not in brief A4)
    "METHOD_NOT_ALLOWED",  # wrong verb (server safety net, not in brief A4)
    "INTERNAL_ERROR",  # unexpected failure, contract-shaped (server safety net, not in brief A4)
]

# Fixed by kind: the engine, not the LLM, decides what a violated clause does.
KIND_ACTION: Dict[str, str] = {
    "per_txn_limit": "escalate",
    "cumulative_limit": "deny",
    "data_scope": "deny",
    "precondition": "deny",
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


ClauseParams = Union[PerTxnParams, CumulativeParams, DataScopeParams, PreconditionParams]
KIND_PARAMS = {
    "per_txn_limit": PerTxnParams,
    "cumulative_limit": CumulativeParams,
    "data_scope": DataScopeParams,
    "precondition": PreconditionParams,
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
    customer_id: str
    refund_total_24h_inr: int
    refund_count_24h: int
    window_hours: int


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


# ---------------------------------------------------------------- health + scenario
class Health(Strict):
    status: Literal["ok"]
    contract_version: str
    llm_available: bool
    active_policy_version: Optional[int]


class ToolSpec(Strict):
    name: ToolName
    description: str
    params: Dict[str, str]


class Customer(Strict):
    customer_id: str
    name: str


class Order(Strict):
    order_id: str
    customer_id: str
    status: OrderStatus
    amount_inr: int
    item: str
    note: Optional[str]


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


# ---------------------------------------------------------------- policy compile / approve
class CompileRequest(Strict):
    policy_text: str = Field(min_length=1, max_length=5000)
    mode: CompileMode = "auto"

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


class AmbiguityAnswer(Strict):
    ambiguity_id: str
    option_id: str


class ApproveRequest(Strict):
    answers: List[AmbiguityAnswer] = []


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


# ---------------------------------------------------------------- live agent
class ChatRequest(Strict):
    message: str = Field(min_length=1, max_length=2000)
    session_customer_id: str = "C-1001"
    enforcement: Enforcement = "on"
    agent_mode: AgentModeRequest = "auto"

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


class ResetRequest(Strict):
    scope: str = "all"


class ResetResponse(Strict):
    scope: str
    cleared_refunds: int
    cleared_decisions: int
    reset_at: str


class DecisionsResponse(Strict):
    decisions: List[Decision]
    total: int
    limit: int


# ---------------------------------------------------------------- fixed cases + report
class CaseStep(Strict):
    tool: str
    args: Dict[str, Any]
    at_offset_hours: float


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


class CasesResponse(Strict):
    cases: List[CaseSpec]
    total: int


class RunTestsRequest(Strict):
    policy_id: Optional[str] = None


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


# Order matters: dependencies first. generate_types.py emits interfaces in this order.
ALL_MODELS = [
    ErrorBody, ErrorEnvelope,
    PerTxnParams, CumulativeParams, DataScopeParams, PreconditionParams, Clause,
    RefundState, Decision,
    Health, ToolSpec, Customer, Order, AttackPreset, Scenario,
    CompileRequest, AmbiguityOption, Ambiguity, PolicyDraft, AmbiguityAnswer, ApproveRequest,
    DiffRow, ApprovedPolicy,
    ChatRequest, ChatResponse, ResetRequest, ResetResponse, DecisionsResponse,
    CaseStep, CaseSpec, CasesResponse, RunTestsRequest, RunResult, CaseResult,
    ClauseCoverage, LatencySummary, Metrics, TestReport,
]

# Named literal aliases that also appear as TS type aliases.
TS_ALIASES = {
    "Outcome": Outcome, "Enforcement": Enforcement, "AgentModeRequest": AgentModeRequest,
    "AgentModeUsed": AgentModeUsed, "CompiledBy": CompiledBy, "CompileMode": CompileMode,
    "ClauseKind": ClauseKind, "ClauseAction": ClauseAction, "CaseType": CaseType,
    "OrderStatus": OrderStatus, "DiffChange": DiffChange, "ToolName": ToolName,
    "ErrorCode": ErrorCode,
}
