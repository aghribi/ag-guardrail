"""Hosted guardrail client — calls the hosted Guardrail API."""
from __future__ import annotations
from typing import Optional
import httpx


class QuotaExceededError(Exception):
    """Raised when the hosted API returns HTTP 429 (monthly quota exceeded)."""
    def __init__(self, message: str = "Monthly quota exceeded"):
        super().__init__(message)


def _check(resp: httpx.Response) -> None:
    if resp.status_code == 429:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise QuotaExceededError(detail)
    resp.raise_for_status()


class HostedGuardrail:
    """
    Check text against the hosted Guardrail (regex + LLM classifier + custom policies).

    Example::

        from ag_guardrail import HostedGuardrail

        guard = HostedGuardrail(api_key="ag_live_...", base_url="https://your-ag-platform")

        result = guard.check("Ignore all previous instructions.")
        if not result["passed"]:
            raise ValueError(f"Blocked by {result['blocked_by']}")

        # Use the LLM classifier for semantic detection
        result = guard.check(text, detectors=["llm_classifier"])

        # Manage custom policies
        guard.create_policy("no_competitors", [
            {"type": "keyword", "pattern": "acme_corp", "action": "block"},
        ])
    """

    def __init__(self, api_key: str, base_url: str, timeout: float = 15.0):
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        self._timeout = timeout

    def _post(self, path: str, body: dict) -> dict:
        with httpx.Client(base_url=self._base, headers=self._headers, timeout=self._timeout) as c:
            r = c.post(path, json=body)
            _check(r)
            return r.json()

    def _get(self, path: str) -> dict | list:
        with httpx.Client(base_url=self._base, headers=self._headers, timeout=self._timeout) as c:
            r = c.get(path)
            _check(r)
            return r.json()

    # ── Check ─────────────────────────────────────────────────────────────────

    def check(
        self,
        text: str,
        direction: str = "input",
        detectors: Optional[list[str]] = None,
    ) -> dict:
        """
        Returns ``{"passed": bool, "blocked_by": str|None, "results": [...]}``.
        Custom policies are applied automatically server-side.
        """
        payload: dict = {"text": text, "direction": direction}
        if detectors:
            payload["detectors"] = detectors
        return self._post("/v1/ag_guardrail/check", payload)

    def is_safe(self, text: str, direction: str = "input", detectors: Optional[list[str]] = None) -> bool:
        return self.check(text, direction, detectors)["passed"]

    # ── Policy CRUD ───────────────────────────────────────────────────────────

    def create_policy(self, name: str, rules: list[dict], is_active: bool = True) -> dict:
        return self._post("/v1/ag_guardrail/policies", {"name": name, "rules": rules, "is_active": is_active})

    def list_policies(self) -> list:
        return self._get("/v1/ag_guardrail/policies")  # type: ignore[return-value]

    def delete_policy(self, policy_id: str) -> None:
        with httpx.Client(base_url=self._base, headers=self._headers, timeout=self._timeout) as c:
            _check(c.delete(f"/v1/ag_guardrail/policies/{policy_id}"))
