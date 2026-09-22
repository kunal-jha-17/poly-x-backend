"""FastAPI app: the 12 endpoints of contract v1.0.0 under /api/v1.

Run with ONE worker (state is in memory and serialised by a lock):
    CORS_ORIGINS="http://localhost:5173" uvicorn app:app --port 8000 --workers 1
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

import llm
from compiler import CompileError
from engine import Engine
from errors import ApiError
from models import (
    CONTRACT_VERSION, ApprovedPolicy, ApproveRequest, CasesResponse, ChatRequest, ChatResponse, CompileRequest,
    DecisionsResponse, Health, PolicyDraft, ResetRequest, ResetResponse, RunTestsRequest, Scenario, TestReport,
)

log = logging.getLogger("cryptix.app")
PREFIX = "/api/v1"


def _error(code: str, message: str, status: int, details: Optional[Dict[str, Any]] = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, "details": details}})


def _cors_origins() -> List[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


def build_router(engine: Engine) -> APIRouter:
    r = APIRouter(prefix=PREFIX)

    @r.get("/health", response_model=Health)
    def health() -> Health:
        return engine.health()

    @r.get("/scenario", response_model=Scenario)
    def get_scenario() -> Scenario:
        return engine.scenario()

    @r.post("/policy/compile", response_model=PolicyDraft)
    def compile_policy(req: CompileRequest) -> PolicyDraft:
        try:
            return engine.compile(req)
        except CompileError as exc:
            raise ApiError("COMPILE_FAILED", str(exc), 422) from exc

    @r.post("/policy/{policy_id}/approve", response_model=ApprovedPolicy)
    def approve_policy(policy_id: str, req: Optional[ApproveRequest] = None) -> ApprovedPolicy:
        return engine.approve(policy_id, req or ApproveRequest())

    @r.get("/policy/active", response_model=ApprovedPolicy)
    def active_policy() -> ApprovedPolicy:
        return engine.active_policy()

    @r.post("/agent/chat", response_model=ChatResponse)
    def chat(req: ChatRequest) -> ChatResponse:
        return engine.chat(req)

    @r.post("/state/reset", response_model=ResetResponse)
    def reset(req: Optional[ResetRequest] = None) -> ResetResponse:
        return engine.reset(req or ResetRequest())

    @r.get("/decisions", response_model=DecisionsResponse)
    def decisions(limit: int = Query(50, ge=1, le=200)) -> DecisionsResponse:
        return engine.list_decisions(limit)

    @r.get("/tests/cases", response_model=CasesResponse)
    def test_cases() -> CasesResponse:
        return engine.cases()

    @r.post("/tests/run", response_model=TestReport)
    def run_tests(req: Optional[RunTestsRequest] = None) -> TestReport:
        return engine.run_tests(req or RunTestsRequest())

    @r.get("/reports/latest", response_model=TestReport)
    def latest_report() -> TestReport:
        return engine.latest_report()

    @r.get("/reports/{report_id}", response_model=TestReport)
    def get_report(report_id: str) -> TestReport:
        return engine.get_report(report_id)

    return r


def create_app(engine: Optional[Engine] = None, init_llm: bool = True) -> FastAPI:
    engine = engine or Engine()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if init_llm:
            client = await asyncio.to_thread(llm.init_client)  # verified by a self-test call, or None
            engine.set_llm(client, client is not None)
            log.info("llm_available=%s", engine.llm_available)
        yield

    app = FastAPI(title="CryptiX Policy-to-Proof Firewall API", version=CONTRACT_VERSION, lifespan=lifespan,
                  redirect_slashes=False)  # no trailing-slash redirects: they break browser CORS
    app.state.engine = engine
    app.include_router(build_router(engine))

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
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - never leak a stack trace; stay contract-shaped
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            response = _error("INTERNAL_ERROR", "Something went wrong on the server. Please retry.", 500)
        response.headers["X-Contract-Version"] = CONTRACT_VERSION
        return response

    # added last => outermost, so CORS headers also appear on errors and X-Contract-Version is readable by the browser
    app.add_middleware(
        CORSMiddleware, allow_origins=_cors_origins(), allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"], expose_headers=["X-Contract-Version"], allow_credentials=False,
    )
    return app


app = create_app()
