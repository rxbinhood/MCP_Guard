"""LLM judge: request shape, JSON validation, retry and fallback, using a mocked HTTP transport."""

import asyncio
import json

import httpx
import pytest

from mcpguard.config import update_settings
from mcpguard.desc_analyzer import llm_judge
from mcpguard.findings import ToolDef

TOOL = ToolDef(name="get_weather", description="Get the weather.",
               inputSchema={"type": "object", "properties": {"city": {"type": "string", "description": "City"}}})
GOOD = {"malicious": False, "confidence": 0.9, "suspicious_text": "", "reason": "documents the tool",
        "claimed_behavior": "fetches weather over the network", "claimed_capabilities": ["network"]}


def _client(replies, seen):
    """replies: list of (status, content-string) returned in order."""
    it = iter(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        status, content = next(it)
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "bad request"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://test")


@pytest.fixture(autouse=True)
def endpoint():
    update_settings(llm_base_url="http://llm.test/v1", llm_model="test-model", llm_api_key="k")


def test_structured_request_and_parse():
    seen: list = []
    j = asyncio.run(llm_judge.judge(TOOL, _client([(200, json.dumps(GOOD))], seen)))
    assert j.claimed_capabilities == ["network"] and not j.malicious
    body = seen[0]
    assert body["response_format"]["type"] == "json_schema" and body["temperature"] == 0
    assert body["messages"][0]["role"] == "system" and "get_weather" in body["messages"][1]["content"]


def test_retries_once_on_invalid_json():
    seen: list = []
    j = asyncio.run(llm_judge.judge(TOOL, _client([(200, "not json"), (200, json.dumps(GOOD))], seen)))
    assert j.confidence == 0.9 and len(seen) == 2
    assert seen[1]["messages"][-1]["role"] == "user"  # corrective follow-up


def test_gives_up_after_second_invalid_json():
    with pytest.raises(llm_judge.JudgeUnavailable):
        asyncio.run(llm_judge.judge(TOOL, _client([(200, "nope"), (200, "still nope")], [])))


def test_falls_back_to_json_object_when_schema_unsupported():
    seen: list = []
    asyncio.run(llm_judge.judge(TOOL, _client([(400, ""), (200, json.dumps(GOOD))], seen)))
    assert seen[0]["response_format"]["type"] == "json_schema"
    assert seen[1]["response_format"]["type"] == "json_object"


def test_tolerates_fences_and_think_blocks():
    content = "<think>hmm</think>\n```json\n" + json.dumps({**GOOD, "confidence": 1.7}) + "\n```"
    j = asyncio.run(llm_judge.judge(TOOL, _client([(200, content)], [])))
    assert j.confidence == 1.0  # clamped


def test_reasoning_models_omit_temperature():
    update_settings(llm_model="gpt-5-mini")
    seen: list = []
    asyncio.run(llm_judge.judge(TOOL, _client([(200, json.dumps(GOOD))], seen)))
    assert "temperature" not in seen[0]
