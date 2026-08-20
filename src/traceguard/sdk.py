"""Customer-side SDK for mediated actions and signed cached policy enforcement."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from traceguard.control.models import (
    ActionKind,
    ActionRequest,
    Decision,
    DecisionResponse,
    HttpAction,
    SignedPolicyBundle,
)
from traceguard.control.service import ControlPlane


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


class PolicyUnavailable(RuntimeError):
    """Raised when neither the control plane nor a valid safe cache can decide."""


class SignedPolicyCache:
    def __init__(self, signing_key: bytes) -> None:
        self._signing_key = signing_key
        self._bundle: SignedPolicyBundle | None = None

    def install(self, bundle: SignedPolicyBundle) -> None:
        unsigned = bundle.model_dump(mode="json", exclude={"signature"})
        expected = hmac.new(self._signing_key, _canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, bundle.signature):
            raise PolicyUnavailable("policy bundle signature is invalid")
        if bundle.expires_at <= datetime.now(UTC):
            raise PolicyUnavailable("policy bundle has expired")
        self._bundle = bundle

    def evaluate(self, action: ActionRequest) -> DecisionResponse:
        bundle = self._bundle
        if bundle is None or bundle.tenant_id != action.tenant_id:
            raise PolicyUnavailable("no policy bundle for tenant")
        if bundle.expires_at <= datetime.now(UTC):
            raise PolicyUnavailable("policy bundle has expired")
        for rule in sorted(bundle.policy.draft.rules, key=lambda item: item.priority, reverse=True):
            if ControlPlane._matches(rule.match, action):
                if rule.decision is Decision.ALLOW and rule.cache_eligible:
                    return DecisionResponse(
                        decision=Decision.ALLOW,
                        reason=f"cached policy: {rule.reason}",
                        policy_id=bundle.policy.policy_id,
                        policy_version=bundle.policy.version,
                        audit_id="cache-pending-reconciliation",
                        from_cache=True,
                    )
                break
        raise PolicyUnavailable("cached policy cannot authorize this action")


class TraceGuardClient:
    """HTTP client with fail-closed remote evaluation and signed cache fallback."""

    def __init__(
        self, base_url: str, bearer_token: str, cache: SignedPolicyCache | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.cache = cache
        self._offline_events: list[ActionRequest] = []

    def evaluate(self, action: ActionRequest) -> DecisionResponse:
        request = Request(
            f"{self.base_url}/v1/actions/evaluate",
            data=action.model_dump_json().encode(),
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:  # nosec B310: URL is caller-configured control plane
                return DecisionResponse.model_validate_json(response.read())
        except (OSError, URLError, TimeoutError) as exc:
            if self.cache is None:
                raise PolicyUnavailable(
                    "control plane unavailable and no signed cache is installed"
                ) from exc
            decision = self.cache.evaluate(action)
            self._offline_events.append(action)
            return decision

    def reconcile(self) -> list[DecisionResponse]:
        events, self._offline_events = self._offline_events, []
        results: list[DecisionResponse] = []
        for action in events:
            results.append(self.evaluate(action))
        return results

    def request_http(self, tenant_id: str, idempotency_key: str, request: HttpAction) -> bytes:
        action = ActionRequest(
            tenant_id=tenant_id,
            idempotency_key=idempotency_key,
            kind=ActionKind.HTTP,
            operation=request.method.upper(),
            target=str(request.url),
            arguments={"headers": dict(request.headers), "json": request.json_body},
        )
        decision = self.evaluate(action)
        if decision.decision is not Decision.ALLOW:
            raise PermissionError(f"TraceGuard denied HTTP action: {decision.reason}")
        body = json.dumps(request.json_body).encode() if request.json_body is not None else None
        outbound = Request(
            str(request.url), data=body, headers=request.headers, method=request.method.upper()
        )
        with urlopen(outbound, timeout=15) as response:  # nosec B310: policy governs the destination
            return response.read()
