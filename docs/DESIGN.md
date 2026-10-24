# Design notes

## Check order for one tool call

1. Verify the token's HMAC chain. Failure: deny (`capability`).
2. Evaluate every caveat (scope, args, budget, expiry, no_sinks). Failure: deny (`capability`).
   The budget check and its increment happen under one lock, so parallel agents cannot overshoot.
3. Policy: first matching glob, else default (`allow` / `ask` / `deny`).
4. Flow check, for sinks only. It can tighten the decision and never loosen it:
   - context tags not covered by the destination's clearance: `deny` (`flow`);
   - untrusted context and decision `allow`: raise to `ask`.
5. `ask` goes to the approver. `deny` never does.
6. Execute, label the result, journal it.

## Why labels cross agent boundaries the way they do

| Edge | Rule | Closes |
|---|---|---|
| parent to child | child starts with the parent's label | data smuggled in the task string |
| child to parent | parent joins the child's final label | laundering through returned text |
| siblings to parent | parent joins all of them after they finish | the split attack |

Siblings run concurrently and cannot see each other's labels, which is safe: each can only send what
it has itself seen.

## Capability model

- Tokens are bearer secrets given to agents. A compromised agent can present any token, which is why
  the scripted attackers are allowed to (`Call(token=...)`) and the broker verifies each one.
- `max_calls` counters are keyed by the signature of the chain prefix, so a child's calls consume the
  budget of every ancestor token it was derived from.
- Delegation depth is carried as a `depth` caveat, so it is part of what the signature protects.

## Deliberately not here (next layers)

| Missing | Why it matters | Planned |
|---|---|---|
| ~~LLM brain adapter~~ | done in 0.2.0 (`llm.py`); still needs a run against live APIs | verified offline only |
| Durable, resumable runs and approvals | crash recovery for long delegations | next (event-source the mesh like AgentKernel) |
| MCP gateway | enforce the same broker in front of external MCP servers | stage 4 |
| Declassification with review | a human or a verified function lowers a label on purpose | stage 5 |
| Eval gate in CI | replay recorded trajectories and fail the build on policy drift | stage 5 |
