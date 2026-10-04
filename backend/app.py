"""FastAPI app: POLY-X contract v1.1.0 under /api/v1.

Run with ONE worker (state is in memory and serialised by a lock):
    CORS_ORIGINS="http://localhost:5173" uvicorn app:app --port 8000 --workers 1

Startup never waits for a model: providers are probed in the background, so the port opens (and /health answers)
immediately after a cold start.
"""
import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

import exports
from compiler import CompileError
from engine import Engine
from errors import ApiError
from models import (
    CONTRACT_VERSION, Approval, ApprovalResolution, ApprovalsResponse, ApprovedPolicy, ApproveRequest, AuditResponse,
    AuditVerifyResponse, BenchRequest, BenchStatus, CaseCreate, CaseSpec, CasesResponse, ChatRequest, ChatResponse,
    CiRunRequest, CiRunResponse, CompileRequest, DecisionsResponse, GenerateRequest, GenerateResponse, GuardRequest,
    GuardResponse, Health, LocalModelConfig, ModelsResponse, Outcome, PolicyBundle, PolicyDiffResponse, PolicyDraft,
    PolicyHistoryResponse, PromptResponse, ResetRequest, ResetResponse, ResolveRequest, RollbackRequest,
    RunTestsRequest, Scenario, ScenariosResponse, TestReport,
)
from security import SECURITY_HEADERS, RateLimiter, client_address

log = logging.getLogger("polyx.app")
PREFIX = "/api/v1"
ScenarioQ = Query(None, max_length=40, description="Scenario pack id: support (default) or devops.")


def _error(code: str, message: str, status: int, details: Optional[Dict[str, Any]] = None,
           headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, "details": details}}, headers=headers)


def _cors_origins() -> List[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


def build_router(engine: Engine) -> APIRouter:
    r = APIRouter(prefix=PREFIX)

    # ------------------------------------------------------------ service
    @r.get("/health", response_model=Health, tags=["service"])
    def health() -> Health:
        return engine.health()

    @r.head("/health", include_in_schema=False)
    def health_head() -> Response:  # uptime monitors send HEAD
        return Response(status_code=200)

    @r.get("/scenario", response_model=Scenario, tags=["service"])
    def get_scenario(scenario: Optional[str] = ScenarioQ) -> Scenario:
        return engine.scenario(scenario)

    @r.get("/scenarios", response_model=ScenariosResponse, tags=["service"])
    def list_scenarios() -> ScenariosResponse:
        return engine.scenarios()

    # ------------------------------------------------------------ models
    @r.get("/models", response_model=ModelsResponse, tags=["models"])
    def models() -> ModelsResponse:
        return engine.models()

    @r.post("/models/refresh", response_model=ModelsResponse, tags=["models"])
    def refresh_models() -> ModelsResponse:
        """Re-test every configured model (for example after starting the local model server)."""
        return engine.refresh_models()

    @r.put("/models/local", response_model=ModelsResponse, tags=["models"])
    def set_local_model(cfg: LocalModelConfig, x_admin_token: Optional[str] = Header(None)) -> ModelsResponse:
        """Point the server at a local / self-hosted OpenAI-compatible model at runtime. Needs the admin token."""
        token = engine.admin_token
        if not token:
            raise ApiError("ADMIN_REQUIRED", "Runtime model configuration is off. Set POLYX_ADMIN_TOKEN on the server to enable it.", 403)
        if not x_admin_token or not hmac.compare_digest(x_admin_token.encode(), token.encode()):
            raise ApiError("ADMIN_REQUIRED", "A valid X-Admin-Token header is required.", 403)
        return engine.set_local_model(cfg)

    # ------------------------------------------------------------ policy: compile, approve, policy-as-code
    @r.post("/policy/compile", response_model=PolicyDraft, tags=["policy"])
    def compile_policy(req: CompileRequest) -> PolicyDraft:
        try:
            return engine.compile(req)
        except CompileError as exc:
            raise ApiError("COMPILE_FAILED", str(exc), 422) from exc

    @r.get("/policy/prompt", response_model=PromptResponse, tags=["policy"])
    def policy_prompt(scenario: Optional[str] = ScenarioQ) -> PromptResponse:
        """The compiler prompt, so a model on the phone can propose clauses and send them to /policy/compile as `proposal`."""
        return engine.prompt(scenario)

    @r.post("/policy/import", response_model=PolicyDraft, tags=["policy"])
    def import_policy(bundle: PolicyBundle) -> PolicyDraft:
        return engine.import_policy(bundle)

    @r.post("/policy/rollback", response_model=ApprovedPolicy, tags=["policy"])
    def rollback_policy(req: RollbackRequest) -> ApprovedPolicy:
        return engine.rollback(req)

    @r.post("/policy/{policy_id}/approve", response_model=ApprovedPolicy, tags=["policy"])
    def approve_policy(policy_id: str, req: Optional[ApproveRequest] = None) -> ApprovedPolicy:
        return engine.approve(policy_id, req or ApproveRequest())

    @r.get("/policy/active", response_model=ApprovedPolicy, tags=["policy"])
    def active_policy(scenario: Optional[str] = ScenarioQ) -> ApprovedPolicy:
        return engine.active_policy(scenario)

    @r.get("/policy/history", response_model=PolicyHistoryResponse, tags=["policy"])
    def policy_history(scenario: Optional[str] = ScenarioQ) -> PolicyHistoryResponse:
        return engine.policy_history(scenario)

    @r.get("/policy/diff", response_model=PolicyDiffResponse, tags=["policy"])
    def policy_diff(from_version: int = Query(..., ge=1), to_version: int = Query(..., ge=1),
                    scenario: Optional[str] = ScenarioQ) -> PolicyDiffResponse:
        return engine.policy_diff(scenario, from_version, to_version)

    @r.get("/policy/export", response_model=PolicyBundle, tags=["policy"])
    def export_policy(scenario: Optional[str] = ScenarioQ, version: Optional[int] = Query(None, ge=1)) -> PolicyBundle:
        return engine.export_policy(scenario, version)

    @r.get("/policy/versions/{version}", response_model=ApprovedPolicy, tags=["policy"])
    def policy_version(version: int, scenario: Optional[str] = ScenarioQ) -> ApprovedPolicy:
        return engine.policy_version(scenario, version)

    # ------------------------------------------------------------ runtime: guard, chat, approvals
    @r.post("/guard/check", response_model=GuardResponse, tags=["runtime"])
    def guard_check(req: GuardRequest) -> GuardResponse:
        """Ask before a tool runs: allow, deny or escalate, with the clause that decided."""
        return engine.guard(req)

    @r.post("/agent/chat", response_model=ChatResponse, tags=["runtime"])
    def chat(req: ChatRequest) -> ChatResponse:
        return engine.chat(req)

    @r.get("/approvals", response_model=ApprovalsResponse, tags=["runtime"])
    def approvals(status: Optional[Literal["pending", "approved", "rejected"]] = None, scenario: Optional[str] = ScenarioQ,
                  limit: int = Query(50, ge=1, le=200)) -> ApprovalsResponse:
        return engine.list_approvals(status, scenario, limit)

    @r.get("/approvals/{ticket_id}", response_model=Approval, tags=["runtime"])
    def approval(ticket_id: str) -> Approval:
        return engine.get_approval(ticket_id)

    @r.post("/approvals/{ticket_id}/resolve", response_model=ApprovalResolution, tags=["runtime"])
    def resolve_approval(ticket_id: str, req: ResolveRequest) -> ApprovalResolution:
        return engine.resolve_approval(ticket_id, req)

    @r.post("/state/reset", response_model=ResetResponse, tags=["runtime"])
    def reset(req: Optional[ResetRequest] = None) -> ResetResponse:
        return engine.reset(req or ResetRequest())

    @r.get("/decisions", response_model=DecisionsResponse, tags=["runtime"])
    def decisions(limit: int = Query(50, ge=1, le=200), scenario: Optional[str] = ScenarioQ,
                  outcome: Optional[Outcome] = None) -> DecisionsResponse:
        return engine.list_decisions(limit, scenario, outcome)

    # ------------------------------------------------------------ audit trail
    @r.get("/audit", response_model=AuditResponse, tags=["audit"])
    def audit(limit: int = Query(100, ge=1, le=500), scenario: Optional[str] = ScenarioQ,
              type: Optional[str] = Query(None, max_length=40, description="Event type prefix, e.g. decision or policy.")) -> AuditResponse:
        return engine.audit_events(limit, scenario, type)

    @r.get("/audit/verify", response_model=AuditVerifyResponse, tags=["audit"])
    def audit_verify() -> AuditVerifyResponse:
        return engine.audit_verify()

    @r.get("/audit/export", tags=["audit"], response_class=PlainTextResponse)
    def audit_export(format: Literal["jsonl", "csv", "json"] = "jsonl") -> Response:
        media = {"jsonl": "application/x-ndjson", "csv": "text/csv", "json": "application/json"}[format]
        return Response(content=engine.audit_export(format), media_type=f"{media}; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="polyx-audit.{format}"'})

    # ------------------------------------------------------------ tests, reports, CI
    @r.get("/tests/cases", response_model=CasesResponse, tags=["tests"])
    def test_cases(scenario: Optional[str] = ScenarioQ) -> CasesResponse:
        return engine.cases(scenario)

    @r.post("/tests/cases", response_model=CaseSpec, tags=["tests"])
    def add_case(req: CaseCreate) -> CaseSpec:
        return engine.add_case(req)

    @r.delete("/tests/cases", response_model=CasesResponse, tags=["tests"])
    def clear_cases(scenario: Optional[str] = ScenarioQ) -> CasesResponse:
        """Remove every custom and generated case. Built-in cases stay."""
        return engine.clear_custom_cases(scenario)

    @r.delete("/tests/cases/{case_id}", response_model=CasesResponse, tags=["tests"])
    def delete_case(case_id: str, scenario: Optional[str] = ScenarioQ) -> CasesResponse:
        return engine.delete_case(case_id, scenario)

    @r.post("/tests/generate", response_model=GenerateResponse, tags=["tests"])
    def generate_cases(req: Optional[GenerateRequest] = None) -> GenerateResponse:
        return engine.generate_cases(req or GenerateRequest())

    @r.post("/tests/run", response_model=TestReport, tags=["tests"])
    def run_tests(req: Optional[RunTestsRequest] = None) -> TestReport:
        return engine.run_tests(req or RunTestsRequest())

    @r.get("/reports/latest", response_model=TestReport, tags=["tests"])
    def latest_report(scenario: Optional[str] = ScenarioQ) -> TestReport:
        return engine.latest_report(scenario)

    @r.get("/reports/{report_id}", response_model=TestReport, tags=["tests"])
    def get_report(report_id: str) -> TestReport:
        return engine.get_report(report_id)

    @r.get("/reports/{report_id}/junit", tags=["tests"], response_class=PlainTextResponse)
    def report_junit(report_id: str) -> Response:
        """JUnit XML for CI test dashboards. report_id may be `latest`."""
        return Response(content=exports.junit_xml(engine.get_report(report_id)), media_type="application/xml; charset=utf-8")

    @r.get("/reports/{report_id}/markdown", tags=["tests"], response_class=PlainTextResponse)
    def report_markdown(report_id: str) -> Response:
        """Markdown summary for a pull request or a job summary. report_id may be `latest`."""
        return Response(content=exports.markdown_summary(engine.get_report(report_id)), media_type="text/markdown; charset=utf-8")

    @r.post("/ci/run", response_model=CiRunResponse, tags=["tests"])
    def ci_run(req: CiRunRequest) -> CiRunResponse:
        try:
            return engine.run_ci(req)
        except CompileError as exc:
            raise ApiError("COMPILE_FAILED", str(exc), 422) from exc

    @r.post("/bench/compile", response_model=BenchStatus, tags=["tests"])
    def start_bench(req: Optional[BenchRequest] = None) -> BenchStatus:
        """Start the compile benchmark in the background. Poll /bench/compile/latest."""
        return engine.start_bench(req or BenchRequest())

    @r.get("/bench/compile/latest", response_model=BenchStatus, tags=["tests"])
    def latest_bench() -> BenchStatus:
        return engine.latest_bench()

    return r


def create_app(engine: Optional[Engine] = None, init_llm: bool = True) -> FastAPI:
    engine = engine or Engine()
    engine.admin_token = os.getenv("POLYX_ADMIN_TOKEN") or None
    limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        probe: Optional[asyncio.Task] = None
        if os.getenv("POLYX_AUTOARM", "") == "1":
            engine.auto_arm()  # rule parser only: instant, no network
            log.info("auto-armed default policies")
        if init_llm:
            probe = asyncio.create_task(asyncio.to_thread(engine.init_providers))  # never blocks startup
        yield
        if probe is not None and not probe.done():
            probe.cancel()

    app = FastAPI(title="POLY-X Policy-to-Proof Firewall API", version=CONTRACT_VERSION, lifespan=lifespan,
                  description="pytest for AI-agent policies: plain-English rules in, a deterministic guard and a before/after proof out.",
                  redirect_slashes=False)  # no trailing-slash redirects: they break browser CORS
    app.state.engine = engine
    app.include_router(build_router(engine))

    @app.get("/", include_in_schema=False)
    def root() -> Dict[str, Any]:
        return {"service": "poly-x", "contract_version": CONTRACT_VERSION, "health": f"{PREFIX}/health", "docs": "/docs"}

    @app.api_route("/healthz", methods=["GET", "HEAD"], include_in_schema=False)
    def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _error(exc.code, exc.message, exc.http_status, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields: List[str] = []
        first = "Request did not match the expected shape."
        for i, err in enumerate(exc.errors()):
            loc = [str(x) for x in err.get("loc", ())]
            name = ".".join(loc[1:]) if len(loc) > 1 else (loc[0] if loc else "body")
            if name not in fields:
                fields.append(name)
            if i == 0:
                first = f"{name}: {err.get('msg', 'invalid')}"
        return _error("VALIDATION_ERROR", f"Invalid request. {first}", 422, {"fields": fields})

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return _error("NOT_FOUND", "No such endpoint. URLs have no trailing slash and start with /api/v1.", 404)
        if exc.status_code == 405:
            return _error("METHOD_NOT_ALLOWED", "That HTTP method is not allowed for this endpoint.", 405)
        return _error("INTERNAL_ERROR", "The request could not be processed.", exc.status_code)

    @app.middleware("http")
    async def _contract_headers(request: Request, call_next):
        response: Response
        length = request.headers.get("content-length", "")
        wait = limiter.check(client_address(request.headers, request.client.host if request.client else None),
                             request.method, request.url.path)
        if length.isdigit() and int(length) > limiter.max_body:
            response = _error("PAYLOAD_TOO_LARGE", f"Request body is larger than {limiter.max_body // 1024} KB.", 413)
        elif wait is not None:
            response = _error("RATE_LIMITED", f"Too many requests. Try again in {wait} second(s).", 429,
                              {"retry_after_s": wait}, {"Retry-After": str(wait)})
        else:
            try:
                response = await call_next(request)
            except Exception:  # noqa: BLE001 - never leak a stack trace; stay contract-shaped
                log.exception("unhandled error on %s %s", request.method, request.url.path)
                response = _error("INTERNAL_ERROR", "Something went wrong on the server. Please retry.", 500)
        response.headers["X-Contract-Version"] = CONTRACT_VERSION
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    # added last => outermost, so CORS headers also appear on errors and X-Contract-Version is readable by the browser
    app.add_middleware(
        CORSMiddleware, allow_origins=_cors_origins(), allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX") or None,
        allow_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        allow_headers=["*"], expose_headers=["X-Contract-Version", "Retry-After", "Content-Disposition"],
        allow_credentials=False, max_age=600,
    )
    return app


app = create_app()
