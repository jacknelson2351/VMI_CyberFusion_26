"""
Provider-agnostic model registry and client construction.

This is the seam the framework was missing: instead of guessing the provider from the
model name and building a bare OpenAI()/Anthropic() client with no base_url, callers
resolve a ModelSpec from config (by id or by role) and build a client from it. Any
OpenAI-compatible endpoint (Shannon abliterated-K3, OpenRouter, DeepInfra, a self-hosted
vLLM box) is reachable by setting base_url.

No local imports beyond config/pricing so the whole app can import this freely.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

VALID_PROVIDER_KINDS = ("openai_compat", "anthropic")


@dataclass
class ModelSpec:
    id: str
    name: str
    provider_kind: str
    model_id: str
    base_url: str = ""
    api_key: str = ""
    api_key_ref: str = ""
    pricing_in: float | None = None
    pricing_out: float | None = None
    caps: dict = field(default_factory=lambda: {"tools": True, "vision": False})
    context: int = 0

    @property
    def pricing(self) -> tuple[float, float] | None:
        if self.pricing_in is None or self.pricing_out is None:
            return None
        return (float(self.pricing_in), float(self.pricing_out))

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)


def key_for(cfg: dict, ref: str) -> str:
    """Resolve an API key by reference: config['keys'][ref], else <REF>_API_KEY env var."""
    ref = (ref or "").strip()
    if not ref:
        return ""
    keys = cfg.get("keys") or {}
    val = (keys.get(ref) or "").strip()
    if val:
        return val
    return (os.environ.get(f"{ref.upper()}_API_KEY") or "").strip()


def _spec_from_entry(cfg: dict, entry: dict) -> ModelSpec | None:
    if not isinstance(entry, dict):
        return None
    mid = (entry.get("id") or "").strip()
    model_id = (entry.get("model_id") or "").strip()
    if not mid or not model_id:
        return None
    kind = (entry.get("provider_kind") or "openai_compat").strip()
    if kind not in VALID_PROVIDER_KINDS:
        kind = "openai_compat"
    pricing = entry.get("pricing") or {}
    caps = entry.get("capabilities") or entry.get("caps") or {}
    ref = (entry.get("api_key_ref") or "").strip()
    return ModelSpec(
        id=mid,
        name=(entry.get("name") or mid).strip(),
        provider_kind=kind,
        model_id=model_id,
        base_url=(entry.get("base_url") or "").strip(),
        api_key=key_for(cfg, ref),
        api_key_ref=ref,
        pricing_in=_num(pricing.get("in")),
        pricing_out=_num(pricing.get("out")),
        caps={
            "tools": bool(caps.get("tools", True)),
            "vision": bool(caps.get("vision", False)),
        },
        context=int(entry.get("context") or 0),
    )


def _num(v):
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def list_models(cfg: dict) -> list[ModelSpec]:
    out = []
    for entry in cfg.get("models") or []:
        spec = _spec_from_entry(cfg, entry)
        if spec:
            out.append(spec)
    return out


def resolve_model(cfg: dict, ref_or_id: str) -> ModelSpec | None:
    """Resolve by model id, role name ('solver'/'aux'), or (legacy) raw model string."""
    ref = (ref_or_id or "").strip()
    if not ref:
        return None
    roles = cfg.get("roles") or {}
    if ref in roles:
        ref = (roles.get(ref) or "").strip()
    models = list_models(cfg)
    for m in models:
        if m.id == ref:
            return m
    # Legacy fallback: match by the raw model_id string.
    for m in models:
        if m.model_id == ref:
            return m
    return None


def resolve_role(cfg: dict, role: str) -> ModelSpec | None:
    """Role -> ModelSpec with graceful fallback.

    solver: role id -> first model -> legacy config['model'] synthesized spec.
    aux:    role id -> solver (so summaries always have somewhere to run).
    """
    role = (role or "solver").strip()
    spec = resolve_model(cfg, role)
    if spec:
        return spec
    if role == "aux":
        return resolve_role(cfg, "solver")
    # Solver fallback chain.
    models = list_models(cfg)
    if models:
        return models[0]
    return _legacy_spec(cfg)


def _legacy_spec(cfg: dict) -> ModelSpec | None:
    """Synthesize a spec from pre-registry config so migration is never required to run."""
    model_id = (cfg.get("solver_model") or cfg.get("model") or "").strip()
    if not model_id:
        return None
    is_anthropic = model_id.lower().startswith(("claude-", "anthropic:", "anthropic/"))
    kind = "anthropic" if is_anthropic else "openai_compat"
    ref = "anthropic" if is_anthropic else "openai"
    key = key_for(cfg, ref) or (cfg.get(f"{ref}_api_key") or "").strip()
    return ModelSpec(
        id=model_id,
        name=model_id,
        provider_kind=kind,
        model_id=model_id,
        api_key=key,
        api_key_ref=ref,
        caps={"tools": True, "vision": True},
    )


def build_client(spec: ModelSpec | None, timeout: float = 180.0, max_retries: int = 2):
    """Return (client, provider_kind). Raises nothing here; callers check for a None client.

    `timeout` is a per-request deadline (seconds). Critically, for streaming it bounds the read
    wait, so a stalled response raises instead of hanging the whole solve forever (this was the
    root cause of a 23-minute stuck run). `max_retries` retries transient failures."""
    if spec is None:
        return None, "openai_compat"
    if spec.provider_kind == "anthropic":
        try:
            from anthropic import Anthropic
        except Exception:
            return None, "anthropic"
        if not spec.api_key:
            return None, "anthropic"
        kwargs = {"api_key": spec.api_key, "timeout": timeout, "max_retries": max_retries}
        if spec.base_url:
            kwargs["base_url"] = spec.base_url
        return Anthropic(**kwargs), "anthropic"
    # openai_compat
    from openai import OpenAI
    if not spec.api_key:
        return None, "openai_compat"
    kwargs = {"api_key": spec.api_key, "timeout": timeout, "max_retries": max_retries}
    if spec.base_url:
        kwargs["base_url"] = spec.base_url
    return OpenAI(**kwargs), "openai_compat"
