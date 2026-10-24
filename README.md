# AgentMesh

![ci](https://github.com/syaiful614/agentmesh/actions/workflows/ci.yml/badge.svg)

**A capability-secure runtime for multi-agent systems.** Delegation can only *narrow* authority,
and information-flow labels follow data across agent boundaries, so a compromised sub-agent
cannot launder private data, widen its permissions, or spend more than it was given.
Standard library only, ~1,900 lines, 62 tests, 12 offline attack scenarios, adapters for real models.

## The problem single-agent guards do not solve

Once agents delegate to other agents, new attacks appear that a per-agent guard cannot see:

| Attack | What goes wrong |
|---|---|
| **Taint laundering** | A sub-agent reads private data and returns it as plain text; the parent, whose own context looks clean, sends it out. |
| **Data smuggled in the task** | The parent hands private data to a "mailer" child inside the task string. |
| **Confused deputy / escalation** | A child (or grandchild) asks for, forges or re-signs more authority than its parent holds. |
| **Budget and depth abuse** | Children multiply calls or recurse without bound. |
| **Split attack** | The three legs (private data, untrusted input, outbound send) are spread over parallel siblings. |

## Two ideas

**1. Attenuating capability tokens** (macaroon-style HMAC chain, `caps.py`). A parent gives a child
`token.attenuate(caveat)`, which needs no key and can only add restrictions. Removing or editing a
caveat breaks the signature. Caveats: tool scope, argument regexes (fail closed), call budget shared
with the parent, expiry, `no_sinks`, delegation depth.

**2. Cross-agent information-flow control** (`labels.py`, `broker.py`, `mesh.py`). Every agent has a
context label (confidentiality tags plus an `untrusted` bit). Labels only grow. A child starts with
its parent's label, its result carries its final label back, and parallel siblings are joined. A tool
that sends data out declares which tags its destination is cleared for. Leaking an uncleared tag is a
**hard deny that no human approval can override**; an untrusted context at a sink needs a human.

All tool calls pass through one `Broker` (token, caveats, policy, flow check) and are written to a
hash-chained journal.

## Try it (offline, no model, no key)

```bash
pip install -e ".[dev]"
agentmesh redteam
```

```text
[PASS] direct_exfil                             -> blocked by the flow check; the careless approver was never asked
[PASS] laundering_via_subagent_result           -> the sub-agent's label came back with its result
[PASS] laundering_via_task_text                 -> the child inherited the parent's label with the task text
[PASS] forged_tokens                            -> a stripped token and a re-signed token both fail verification
[PASS] delegation_cannot_widen                  -> asking for more than the parent holds changes nothing
[PASS] call_budget_is_shared                    -> parent and child draw on one budget of 3
[PASS] parallel_siblings_are_joined             -> labels of parallel siblings are joined in the parent
...
12/12 attack scenarios contained
```

```bash
agentmesh redteam --journal-dir runs/   # keep one journal per scenario
agentmesh show runs/laundering_via_task_text.db
agentmesh verify runs/laundering_via_task_text.db
```

## Library

```python
from agentmesh import Authority, Broker, Call, Delegate, Journal, Mesh, default_policy
from agentmesh.demo_tools import make_registry, make_world

world = make_world()
broker = Broker(Authority(b"use-a-real-secret-key"), make_registry(world), Journal(), default_policy())
mesh = Mesh(broker)


def researcher(view):  # a brain is a generator: yield actions, get observations
    note = yield Call("read_note", {"name": "plan"})
    return note.text


def lead(view):
    r = yield Delegate(
        "researcher", "read the plan", researcher, caveats=({"type": "tools", "allow": ["read_*"]},)
    )
    return r.text


token = broker.authority.mint("root")
print(mesh.run("summarise the plan", lead, token).output)
```

A tool declares what it does; the security layer reasons about these facts, never about what a model
claims: `produces=` (the label of its output), `sink=True`, `clearance=` (tags the destination may
receive), `mutates=`.

## Real models

```bash
agentmesh live --provider fake              # a simulated gullible model, no key needed
agentmesh live --provider fake-delegating   # same, but it delegates the reading to a sub-agent

# Anthropic (the key is read from the environment, never from the command line)
$env:ANTHROPIC_API_KEY = "..."              # PowerShell; use export on Linux/macOS
agentmesh live --provider anthropic --model <model-name> --trials 5

# Any OpenAI-compatible server, e.g. a local Ollama model
agentmesh live --provider openai --base-url http://localhost:11434/v1 --model <model-name> --trials 5
```

Each trial reports three separate facts: did the model **follow** the injected instruction, did the
mesh **block** that attempt, did the secret **leak**. If the model never follows the injection, the
report says the mesh was never exercised, so a model's good behaviour is not counted as a defence.
Cost is bounded by the token (`max_calls`, `depth`), not by trusting the model. `make_brain` shows a
model only the tools its token allows and offers a `delegate` tool; several delegate calls in one
turn run as parallel siblings.

## Why the tests can be trusted

Passing tests prove little unless they can fail. `tests/test_redteam.py` switches a defence off and
asserts that the matching attack then **succeeds**: without the flow check `direct_exfil` leaks; without
label propagation all three laundering scenarios leak. The attacker is also given a careless approver
that approves everything, so the denials shown do not depend on a human noticing.

## Limitations (read these)

- **Labels and tool declarations are the trust root.** A tool that sends data out but is not marked
  `sink=True`, or one that returns private data without a label, defeats the flow check.
- The context label is **conservative**: it tracks what an agent has seen, not which output depends on
  what. Once an agent has seen private data it cannot send to an uncleared destination, even for an
  unrelated reason. Use a fresh agent for unrelated work.
- The adapters are tested against a local fake HTTP server and a simulated gullible model, **not against
  live provider APIs**, and no result about how real models behave is claimed. Tools run in-process
  (no sandbox), single node, no durable resume (see [docs/DESIGN.md](docs/DESIGN.md)).
- Approvals are a synchronous callback here, not durable across process restarts.
- Journal entries clip long values, and hash chaining does not detect truncation of the tail.
- The root key is held in memory by the `Authority`; key management is out of scope.

## Layout

```text
src/agentmesh/
  labels.py      information-flow labels (join-only)
  caps.py        attenuating capability tokens and caveat evaluation
  broker.py      the single checkpoint: token, caveats, policy, flow, approval, journal
  mesh.py        multi-agent runtime: delegation, parallel siblings, label propagation
  journal.py     hash-chained SQLite audit log
  tools.py       tools with labels, sink flag and clearance
  demo_tools.py  a world that reproduces the exfiltration setup
  redteam.py     12 scripted attack scenarios
  llm.py         Anthropic and OpenAI-compatible clients, model-driven brain, test double
  live.py        the injection scenario against a model, several trials
  cli.py         redteam, live, show, verify
```

## License

MIT
