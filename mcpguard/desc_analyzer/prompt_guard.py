"""Layer 2 of the description analyzer: Meta Llama Prompt Guard 2 injection scoring (optional).

Two ways to provide the classifier:
  * MCPGUARD_PROMPTGUARD_URL - an HTTP service (see services/promptguard) accepting
    POST {"texts": [...]} and returning {"scores": [...]} (probability of injection)
  * in-process via ``transformers`` if installed and the model is available locally

If neither is available the layer reports itself offline and is skipped.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from mcpguard.config import get_settings

log = logging.getLogger(__name__)

_pipeline: Any = None
_load_error: str | None = None
_status_cache: tuple[float, bool, str] | None = None


def _load_local() -> Any:
    """Load the HF pipeline once. Never raises; records the error instead."""
    global _pipeline, _load_error
    if _pipeline is not None or _load_error is not None:
        return _pipeline
    try:
        from transformers import pipeline  # type: ignore[import-not-found]

        _pipeline = pipeline("text-classification", model=get_settings().promptguard_model,
                             truncation=True, max_length=512)
    except Exception as exc:  # noqa: BLE001 - optional dependency, any failure means offline
        _load_error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
    return _pipeline


def status() -> tuple[bool, str]:
    """(available, detail). Cached for 30s so health checks stay cheap."""
    global _status_cache
    now = time.time()
    if _status_cache and now - _status_cache[0] < 30:
        return _status_cache[1], _status_cache[2]
    s = get_settings()
    if s.promptguard_url:
        try:
            r = httpx.get(s.promptguard_url.rstrip("/") + "/health", timeout=3)
            ok, detail = r.status_code == 200, f"service at {s.promptguard_url}"
        except httpx.HTTPError as exc:
            ok, detail = False, f"service unreachable: {exc.__class__.__name__}"
    else:
        try:
            import transformers  # type: ignore[import-not-found] # noqa: F401

            ok, detail = True, f"in-process ({s.promptguard_model}, loads on first use)"
            if _load_error:
                ok, detail = False, _load_error
        except ImportError:
            ok, detail = False, "not installed (pip install 'mcpguard[promptguard]' or set MCPGUARD_PROMPTGUARD_URL)"
    _status_cache = (now, ok, detail)
    return ok, detail


def _chunks(text: str, size: int = 1500) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]


def score_texts(texts: list[str]) -> list[float] | None:
    """Injection probability per text (max over chunks), or None if the layer is offline."""
    if not texts:
        return []
    s = get_settings()
    if s.promptguard_url:
        try:
            r = httpx.post(s.promptguard_url.rstrip("/") + "/score", json={"texts": texts}, timeout=30)
            r.raise_for_status()
            return [float(x) for x in r.json()["scores"]]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("Prompt Guard service failed: %s", exc)
            return None
    pipe = _load_local()
    if pipe is None:
        return None
    scores: list[float] = []
    for text in texts:
        best = 0.0
        for chunk in _chunks(text):
            out = pipe(chunk, top_k=None)
            # Prompt Guard 2 labels: LABEL_0 = benign, LABEL_1 = malicious.
            for item in out:
                if item["label"] in ("LABEL_1", "MALICIOUS", "INJECTION", "JAILBREAK"):
                    best = max(best, float(item["score"]))
        scores.append(best)
    return scores
