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
    PolicyDraft,
    ResolveReviewRequest,
    Role,
)
from traceguard.control.service import AuthorizationError, ControlPlane, redact

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
    app = FastAPI(title="TraceGuard Control Plane", version="1.0.0")

    def actor(authorization: Annotated[str | None, Header()] = None) -> Actor:
        try:
            return identity(authorization)
        except AuthorizationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.exception_handler(AuthorizationError)
    async def forbidden(_: Request, exc: AuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/actions/evaluate")
    def evaluate(action: ActionRequest, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.evaluate(current, action).model_dump(mode="json")

    @app.get("/v1/policies/bundle")
    def policy_bundle(tenant_id: str, current: Actor = Depends(actor)) -> dict[str, Any]:
        return control.signed_bundle(tenant_id, current, timedelta(minutes=15)).model_dump(
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
            arguments={"model": payload.get("model"), "messages": redact(messages)},
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
    key = os.environ.get("TRACEGUARD_SIGNING_KEY", "development-key-change-me-32-bytes!").encode()
    tokens = {
        os.environ.get("TRACEGUARD_DEV_TOKEN", "development-token"): Actor(
            subject="development-agent", roles={Role.AGENT}, service_key_id="development"
        )
    }
    return create_app(ControlPlane(key), token_resolver(tokens))


app = _development_app()


def run() -> None:
    import uvicorn

    uvicorn.run("traceguard.control.api:app", host="0.0.0.0", port=8080)
