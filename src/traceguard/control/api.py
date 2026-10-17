"""FastAPI boundary for the TraceGuard v1 control plane."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import timedelta
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from traceguard.control.models import (
    ActionRequest,
    Actor,
    GrantRequest,
    GrantValidation,
    PolicyDraft,
    ResolveReviewRequest,
    Role,
    TaskRegistration,
)
from traceguard.control.service import AuthorizationError, ControlPlane, IdempotencyConflict

IdentityResolver = Callable[[str | None], Actor]


def token_resolver(tokens: dict[str, Actor]) -> IdentityResolver:
    """Resolve opaque service/OIDC-session tokens supplied by an upstream identity provider."""

    def resolve(authorization: str | None) -> Actor:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthorizationError("missing bearer credential")
        actor = tokens.get(authorization.removeprefix("Bearer "))
        if actor is None:
            raise AuthorizationError("invalid bearer credential")
        return actor

    return resolve


def create_app(control: ControlPlane, identity: IdentityResolver) -> FastAPI:
    from traceguard.control.execution import ExecutionAuthority

    execution = ExecutionAuthority(control)
    app = FastAPI(title="TraceGuard Control Plane", version="1.0.0")

    def actor(authorization: Annotated[str | None, Header()] = None) -> Actor:
        try:
            return identity(authorization)
        except AuthorizationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.exception_handler(AuthorizationError)
    async def forbidden(_: Request, exc: AuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(IdempotencyConflict)
    async def conflict(_: Request, exc: IdempotencyConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(KeyError)
    async def missing(_: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": "resource not found"})

    @app.exception_handler(ValueError)
    async def invalid(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.post("/v1/tasks/register")
    def register_task(
        tenant_id: str, registration: TaskRegistration, current: Actor = Depends(actor)
    ) -> dict[str, str]:
        return {"authority_digest": execution.register(tenant_id, current, registration)}

    @app.post("/v1/execution/grants")
    def issue_grant(body: GrantRequest, current: Actor = Depends(actor)) -> dict[str, Any]:
        return execution.issue(
            current, body.action, body.executor_audience, body.review_id
        ).model_dump(mode="json")

    @app.post("/v1/execution/validate")
    def validate_grant(body: GrantValidation, current: Actor = Depends(actor)) -> dict[str, bool]:
        execution.validate(current, body.action, body.grant)
        return {"valid": True}

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/actions/evaluate")
    def evaluate(action: ActionRequest, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.evaluate(current, action).model_dump(mode="json")

    @app.get("/v1/policies/bundle")
    def policy_bundle(tenant_id: str, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.signed_bundle(tenant_id, current, timedelta(minutes=5)).model_dump(
            mode="json"
        )

    @app.post("/v1/policies/drafts")
    def create_draft(
        tenant_id: str, draft: PolicyDraft, current: Actor = Depends(actor)
    ) -> dict[str, Any]:
        return control.create_draft(tenant_id, current, draft).model_dump(mode="json")

    @app.post("/v1/policies/{policy_id}/submit")
    def submit_policy(
        policy_id: str, tenant_id: str, current: Actor = Depends(actor)
    ) -> dict[str, Any]:
        return control.submit_policy(tenant_id, current, policy_id).model_dump(mode="json")

    @app.post("/v1/policies/{policy_id}/approve")
    def approve_policy(
        policy_id: str, tenant_id: str, current: Actor = Depends(actor)
    ) -> dict[str, Any]:
        return control.approve_policy(tenant_id, current, policy_id).model_dump(mode="json")

    @app.post("/v1/policies/{policy_id}/rollback")
    def rollback(policy_id: str, tenant_id: str, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.rollback(tenant_id, current, policy_id).model_dump(mode="json")

    @app.post("/v1/reviews/{review_id}/resolve")
    def resolve_review(
        review_id: str, tenant_id: str, body: ResolveReviewRequest, current: Actor = Depends(actor)
    ) -> dict[str, Any]:
        return control.resolve_review(
            tenant_id, current, review_id, body.resolution, body.reason
        ).model_dump(mode="json")

    @app.get("/v1/audit/export")
    def export_audit(tenant_id: str, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.export_audit(tenant_id, current)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request, current: Actor = Depends(actor)) -> JSONResponse:
        """OpenAI-compatible policy gate; forwarding belongs to a configured upstream adapter."""
        payload = await request.json()
        messages = payload.get("messages", [])
        action = ActionRequest(
            tenant_id=request.headers.get("X-TraceGuard-Tenant", ""),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            kind="model_request",
            operation="chat.completions",
            arguments={"model": payload.get("model"), "messages": messages},
        )
        decision = control.evaluate(current, action)
        if decision.decision.value != "ALLOW":
            return JSONResponse(status_code=403, content=decision.model_dump(mode="json"))
        # An upstream provider adapter must be configured explicitly; silently forwarding is unsafe.
        return JSONResponse(
            status_code=501,
            content={
                "detail": "model upstream adapter is not configured",
                "decision": decision.model_dump(mode="json"),
            },
        )

    return app


def _development_app() -> FastAPI:
    if os.environ.get("TRACEGUARD_ALLOW_IN_MEMORY") != "1":
        raise RuntimeError("In-memory API requires TRACEGUARD_ALLOW_IN_MEMORY=1; development only")
    key = os.environ.get("TRACEGUARD_SIGNING_KEY", "")
    token = os.environ.get("TRACEGUARD_DEV_TOKEN", "")
    if len(key.encode()) < 32 or key == "development-key-change-me-32-bytes!":
        raise RuntimeError("TRACEGUARD_SIGNING_KEY must be a dedicated key of at least 32 bytes")
    if len(token) < 32 or token == "development-token":
        raise RuntimeError(
            "TRACEGUARD_DEV_TOKEN must be a dedicated token of at least 32 characters"
        )
    tenant = os.environ.get("TRACEGUARD_DEV_TENANT", "tenant-a")
    tokens = {
        token: Actor(
            subject="development-agent",
            roles={Role.AGENT},
            service_key_id="development",
            tenant_ids={tenant},
        )
    }
    return create_app(ControlPlane(key.encode()), token_resolver(tokens))


def run() -> None:
    import uvicorn

    uvicorn.run(
        "traceguard.control.api:_development_app",
        factory=True,
        host="0.0.0.0",
        port=8080,
        workers=1,
    )
