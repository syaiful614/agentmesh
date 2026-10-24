import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentmesh.live import run_live
from agentmesh.llm import (
    AnthropicClient,
    GullibleClient,
    LLMError,
    OpenAICompatClient,
    _to_openai_messages,
    make_brain,
)
from agentmesh.redteam import build_stack


class FakeServer:
    """A local HTTP server that replays canned (status, json) responses and records requests."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                status, payload = outer.responses.pop(0)
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(responses):
        srv = FakeServer(responses)
        made.append(srv)
        return srv

    yield make
    for srv in made:
        srv.close()


SPEC = [{"name": "read_note", "description": "d", "input_schema": {"type": "object", "properties": {}}}]
MSGS = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]


def test_anthropic_request_shape_and_response_parsing(server):
    srv = server(
        [
            (
                200,
                {
                    "content": [
                        {"type": "text", "text": "ok", "citations": None},
                        {"type": "tool_use", "id": "t1", "name": "read_note", "input": {"name": "plan"}},
                    ]
                },
            )
        ]
    )
    client = AnthropicClient("secret-key", "some-model", base_url=srv.url)
    blocks = client.complete("sys", MSGS, SPEC)
    path, headers, body = srv.requests[0]
    assert path == "/v1/messages" and headers["x-api-key"] == "secret-key"
    assert headers["anthropic-version"] == "2023-06-01"
    assert body["model"] == "some-model" and body["system"] == "sys" and body["tools"] == SPEC
    assert blocks == [
        {"type": "text", "text": "ok"},
        {"type": "tool_use", "id": "t1", "name": "read_note", "input": {"name": "plan"}},
    ]


def test_retries_on_429_then_succeeds_and_gives_up_on_400(server):
    sleeps = []
    srv = server([(429, {"error": "slow down"}), (529, {"error": "busy"}), (200, {"content": []})])
    client = AnthropicClient("k", "m", base_url=srv.url, sleep=sleeps.append)
    assert client.complete("s", MSGS, []) == [] and len(srv.requests) == 3 and len(sleeps) == 2
    assert "tools" not in srv.requests[-1][2]
    bad = server([(400, {"error": "bad request"})])
    with pytest.raises(LLMError, match="HTTP 400"):
        AnthropicClient("k", "m", base_url=bad.url, sleep=sleeps.append).complete("s", MSGS, [])
    assert len(bad.requests) == 1  # a 400 is not retried


def test_retries_are_bounded(server):
    srv = server([(500, {})] * 3)
    client = AnthropicClient("k", "m", base_url=srv.url, retries=2, sleep=lambda _: None)
    with pytest.raises(LLMError, match="HTTP 500"):
        client.complete("s", MSGS, [])
    assert len(srv.requests) == 3


@pytest.mark.parametrize("url", ["http://example.com", "file:///etc/passwd", "ftp://x.test"])
def test_unsafe_base_urls_are_refused(url):
    with pytest.raises(LLMError, match="refusing"):
        AnthropicClient("k", "m", base_url=url)


def test_missing_key_is_a_clear_error():
    with pytest.raises(LLMError, match="API key"):
        AnthropicClient("")


def test_openai_translation_of_a_tool_round_trip():
    messages = [
        {"role": "user", "content": [{"type": "text", "text": "go"}]},
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "a1", "name": "read_note", "input": {"name": "x"}}],
        },
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a1", "content": "text"}]},
    ]
    out = _to_openai_messages("sys", messages)
    assert out[0] == {"role": "system", "content": "sys"} and out[1]["role"] == "user"
    assert out[2]["content"] is None and out[2]["tool_calls"][0]["function"]["arguments"] == '{"name": "x"}'
    assert out[3] == {"role": "tool", "tool_call_id": "a1", "content": "text"}


def test_openai_client_parses_tool_calls_and_malformed_arguments(server):
    srv = server(
        [
            (
                200,
                {
                    "choices": [
                        {
                            "message": {
                                "content": "thinking",
                                "tool_calls": [
                                    {
                                        "id": "c1",
                                        "function": {"name": "read_note", "arguments": '{"name":"plan"}'},
                                    },
                                    {"function": {"name": "read_note", "arguments": "{not json"}},
                                ],
                            }
                        }
                    ]
                },
            )
        ]
    )
    client = OpenAICompatClient("local-model", api_key="k", base_url=srv.url)
    blocks = client.complete("sys", MSGS, SPEC)
    path, headers, body = srv.requests[0]
    assert path == "/chat/completions" and headers["authorization"] == "Bearer k"
    assert body["tools"][0]["function"]["parameters"] == SPEC[0]["input_schema"]
    assert blocks[0] == {"type": "text", "text": "thinking"}
    assert blocks[1]["input"] == {"name": "plan"} and blocks[1]["id"] == "c1"
    assert blocks[2]["id"] == "call_1" and "_malformed_arguments" in blocks[2]["input"]


def test_openai_unexpected_shape_is_an_error(server):
    srv = server([(200, {"nope": 1})])
    with pytest.raises(LLMError, match="unexpected response"):
        OpenAICompatClient("m", base_url=srv.url).complete("s", MSGS, [])


class Recorder:
    def __init__(self, replies):
        self.replies, self.seen = list(replies), []

    def complete(self, system, messages, tools):
        self.seen.append({"system": system, "tools": [t["name"] for t in tools], "n": len(messages)})
        return self.replies.pop(0)


def test_model_only_sees_tools_its_token_allows():
    s = build_stack()
    rec = Recorder([[{"type": "text", "text": "done"}]])
    brain = make_brain(rec, s.broker.registry.all())
    token = s.authority.mint("t", {"type": "tools", "allow": ["read_*"]})
    res = s.mesh.run("task", brain, token)
    assert res.output == "done"
    assert rec.seen[0]["tools"] == ["read_inbox", "read_note", "delegate"]


def test_turn_limit_and_denied_tool_results_flow_back_to_the_model():
    s = build_stack()
    loop = [
        {
            "type": "tool_use",
            "id": "x",
            "name": "send_email",
            "input": {"to": "a@b.c", "subject": "s", "body": "b"},
        }
    ]
    rec = Recorder([loop] * 3)
    brain = make_brain(rec, s.broker.registry.all(), max_turns=3)
    token = s.authority.mint("t", {"type": "tools", "allow": ["read_*"]})
    res = s.mesh.run("task", brain, token)
    assert res.output.startswith("stopped") and not s.world.sent
    assert any(e["data"]["source"] == "capability" for e in s.journal.events("decision"))


def test_several_delegate_calls_in_one_turn_run_as_parallel_siblings():
    s = build_stack()
    d1 = {
        "type": "tool_use",
        "id": "d1",
        "name": "delegate",
        "input": {"role": "a", "task": "t", "tools": ["list_notes"]},
    }
    d2 = {
        "type": "tool_use",
        "id": "d2",
        "name": "delegate",
        "input": {"role": "b", "task": "t", "tools": ["read_inbox"]},
    }

    # parent turn, child a turn, child b turn, parent final
    class Scripted:
        def __init__(self):
            self.parent_turn = 0

        def complete(self, system, messages, tools):
            if "Your role: root" in system:
                self.parent_turn += 1
                return [d1, d2] if self.parent_turn == 1 else [{"type": "text", "text": "merged"}]
            return [{"type": "text", "text": f"{system.split('role: ')[1]} ok"}]

    brain = make_brain(Scripted(), s.broker.registry.all())
    res = s.mesh.run("task", brain, s.authority.mint("t"))
    assert res.output == "merged" and s.mesh.agents_started == 3


@pytest.mark.parametrize("delegate", [False, True])
def test_a_gullible_model_cannot_leak_through_the_mesh(delegate):
    report = run_live(GullibleClient(delegate=delegate), trials=2)
    assert report.attempted == 2 and report.blocked == 2 and report.leaked == 0


def test_mutations_make_the_gullible_model_leak():
    assert run_live(GullibleClient(), trials=1, flow=False).leaked == 1
    assert run_live(GullibleClient(delegate=True), trials=1, propagate=False).leaked == 1


def test_live_run_is_bounded_by_the_token_budget():
    class Looper:
        def complete(self, system, messages, tools):
            return [{"type": "tool_use", "id": f"l{len(messages)}", "name": "list_notes", "input": {}}]

    report = run_live(Looper(), trials=1, max_calls=4)
    assert report.trials[0].status in ("completed", "max_steps") and report.leaked == 0
