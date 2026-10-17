"""Customer-side SDK for mediated actions and signed cached policy enforcement."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from traceguard.control.models import (
    ActionKind,
    ActionRequest,
    Decision,
    DecisionResponse,
    HttpAction,
    SignedPolicyBundle,
)
from traceguard.control.service import action_digest
from traceguard.control.signing import verify
from traceguard.policy.matching import select_rule
from traceguard.policy.network import PublicHTTPTransport


class PolicyUnavailable(RuntimeError):
    """Neither remote policy nor a scoped read-only offline grant can decide."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


urlopen = build_opener(ProxyHandler({}), NoRedirects()).open


class SignedPolicyCache:
    def __init__(
        self,
        public_key: bytes,
        *,
        tenant_id: str,
        audience: str,
        service_key_id: str,
        key_id: str = "development-ed25519-v1",
        minimum_epoch: int = 0,
    ) -> None:
        self._public_key = public_key
        self.tenant_id, self.audience = tenant_id, audience
        self.service_key_id, self.key_id = service_key_id, key_id
        self._minimum_epoch = minimum_epoch
        self._bundle_json: str | None = None

    def install(self, bundle: SignedPolicyBundle) -> None:
        unsigned = bundle.model_dump(mode="json", exclude={"signature"})
        if bundle.key_id != self.key_id or not verify(self._public_key, unsigned, bundle.signature):
            raise PolicyUnavailable("policy bundle signature or key is invalid")
        if (
            bundle.tenant_id != self.tenant_id
            or bundle.policy.tenant_id != self.tenant_id
            or bundle.audience != self.audience
            or bundle.service_key_id != self.service_key_id
            or bundle.policy.status.value != "active"
            or bundle.policy_epoch < self._minimum_epoch
        ):
            raise PolicyUnavailable("policy bundle audience, scope or epoch is invalid")
        now = datetime.now(UTC)
        if (
            bundle.issued_at.tzinfo is None
            or bundle.expires_at.tzinfo is None
            or bundle.expires_at <= now
            or bundle.issued_at > now + timedelta(seconds=30)
            or not timedelta(0) < bundle.expires_at - bundle.issued_at <= timedelta(minutes=5)
        ):
            raise PolicyUnavailable("policy bundle lifetime is invalid or expired")
        self._bundle_json = bundle.model_dump_json()
        self._minimum_epoch = bundle.policy_epoch

    def evaluate(self, action: ActionRequest) -> DecisionResponse:
        if self._bundle_json is None:
            raise PolicyUnavailable("no signed bundle is installed")
        bundle = SignedPolicyBundle.model_validate_json(self._bundle_json)
        if bundle.expires_at <= datetime.now(UTC) or action.tenant_id != self.tenant_id:
            raise PolicyUnavailable("policy bundle has expired or tenant mismatches")
        if (
            action.kind is not ActionKind.HTTP
            or action.operation not in {"GET", "HEAD"}
            or action.arguments.get("json") is not None
        ):
            raise PolicyUnavailable("offline authorization supports read-only HTTP only")
        rule = select_rule(bundle.policy, action)
        if rule is not None and rule.decision is Decision.ALLOW and rule.cache_eligible:
            return DecisionResponse(
                decision=Decision.ALLOW,
                reason=f"cached policy: {rule.reason}",
                policy_id=bundle.policy.policy_id,
                policy_version=bundle.policy.version,
                audit_id="cache-pending-reconciliation",
                from_cache=True,
                action_digest=action_digest(action),
            )
        raise PolicyUnavailable("cached policy cannot authorize this action")


class TraceGuardClient:
    """HTTP client with fail-closed remote evaluation and signed cache fallback."""

    def __init__(
        self,
        base_url: str,
        bearer_token: str,
        cache: SignedPolicyCache | None = None,
        *,
        http_transport: PublicHTTPTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.cache = cache
        self.http_transport = http_transport or PublicHTTPTransport()
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
            return self._remote(request, action)
        except HTTPError as exc:
            raise PolicyUnavailable(
                f"control plane explicitly rejected request ({exc.code})"
            ) from exc
        except (OSError, URLError, TimeoutError) as exc:
            import ssl

            if isinstance(getattr(exc, "reason", exc), ssl.SSLError):
                raise PolicyUnavailable("control-plane TLS verification failed") from exc
            if self.cache is None:
                raise PolicyUnavailable(
                    "control plane unavailable and no signed cache is installed"
                ) from exc
            decision = self.cache.evaluate(action)
            if len(self._offline_events) >= 1000:
                raise PolicyUnavailable("offline decision reconciliation queue is full") from exc
            self._offline_events.append(action.model_copy(deep=True))
            return decision

    def _remote(self, request: Request, action: ActionRequest) -> DecisionResponse:
        with urlopen(request, timeout=5) as response:
            payload = response.read(1_048_577)
        if len(payload) > 1_048_576:
            raise PolicyUnavailable("control-plane response exceeds limit")
        decision = DecisionResponse.model_validate_json(payload)
        if decision.action_digest != action_digest(action):
            raise PolicyUnavailable("control-plane decision does not bind the requested action")
        return decision

    def reconcile(self) -> list[DecisionResponse]:
        results = []
        while self._offline_events:
            action = self._offline_events[0]
            request = Request(
                f"{self.base_url}/v1/actions/evaluate",
                data=action.model_dump_json().encode(),
                headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            results.append(self._remote(request, action))
            self._offline_events.pop(0)
        return results

    def request_http(self, tenant_id: str, idempotency_key: str, request: HttpAction) -> bytes:
        request = request.model_copy(deep=True)
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
        return self.http_transport.request(
            request.method.upper(), str(request.url), dict(request.headers), request.json_body
        )
