"""Tiny HTTP wrapper around Meta Llama Prompt Guard 2 (open weights, Llama 4 Community License).

POST /score {"texts": [...]} -> {"scores": [...]}  (probability that each text is a prompt injection)
GET  /health
Long texts are split into chunks and the maximum chunk score is returned.
"""

import os

from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline

MODEL = os.environ.get("PROMPTGUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
classifier = pipeline("text-classification", model=MODEL, truncation=True, max_length=512,
                      token=os.environ.get("HF_TOKEN") or None)
app = FastAPI(title="Prompt Guard 2 service")


class ScoreRequest(BaseModel):
    texts: list[str]


def _score(text: str) -> float:
    chunks = [text[i:i + 1500] for i in range(0, len(text), 1500)] or [""]
    best = 0.0
    for chunk in chunks:
        for item in classifier(chunk, top_k=None):
            if item["label"] in ("LABEL_1", "MALICIOUS"):
                best = max(best, float(item["score"]))
    return best


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL}


@app.post("/score")
def score(req: ScoreRequest) -> dict:
    return {"scores": [_score(t) for t in req.texts]}
