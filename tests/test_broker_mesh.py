from agentmesh import Call, Delegate, Label, Parallel, private
from agentmesh.broker import Action, deny_all
from agentmesh.redteam import build_stack, denied_by

RO = {"type": "tools", "allow": ["read_*", "list_*"]}


def _run(brain, *caveats, **stack_kwargs):
    s = build_stack(**stack_kwargs)
    return s, s.mesh.run("t", brain, s.authority.mint("root", *caveats))


def test_unknown_tool_is_denied_without_running_anything():
    def brain(view):
        r = yield Call("rm_rf", {})
        return r.status

    s, res = _run(brain)
    assert res.output == "denied" and denied_by(s.journal, "unknown_tool")


def test_tool_errors_are_returned_not_raised():
    def brain(view):
        r = yield Call("read_note", {"name": "missing"})
        return r.status

    assert _run(brain)[1].output == "error"


def test_reads_are_allowed_and_label_the_context():
    def brain(view):
        yield Call("read_note", {"name": "plan"})
        yield Call("read_inbox")
        return "x"

    _, res = _run(brain)
    assert res.label == Label(frozenset({"notes"}), True)


def test_denied_calls_do_not_taint_the_context():
    def brain(view):
        yield Call("read_note", {"name": "plan"})
        return "x"

    _, res = _run(brain, {"type": "tools", "allow": ["list_*"]})
    assert res.label.is_clean


def test_hard_flow_denial_cannot_be_overridden_by_a_human():
    def brain(view):
        yield Call("read_note", {"name": "budget"})
        r = yield Call("post_public", {"text": "leak"})
        return r.status

    s, res = _run(brain)  # approver approves everything
    assert res.output == "denied" and not s.world.posted
    assert s.journal.events("approval") == []  # nobody was even asked


def test_public_data_can_be_published_after_approval():
    def brain(view):
        r = yield Call("post_public", {"text": "hello"})
        return r.status

    s, res = _run(brain)
    assert res.output == "ok" and s.world.posted == ["hello"]
    assert [e["data"]["approved"] for e in s.journal.events("approval")] == [True]


def test_declined_approval_means_no_side_effect():
    def brain(view):
        r = yield Call("post_public", {"text": "hello"})
        return r.status

    s, res = _run(brain, approver=deny_all)
    assert res.output == "denied" and not s.world.posted


def test_delegation_returns_child_output_and_label():
    def child(view):
        n = yield Call("read_note", {"name": "plan"})
        return n.text

    def brain(view):
        r = yield Delegate("c", "go", child, (RO,))
        return r.text

    _, res = _run(brain)
    assert res.output == "launch in March" and "notes" in res.label.conf


def test_child_starts_with_the_parents_label():
    seen = {}

    def child(view):
        seen["label"] = view.label
        return "ok"
        yield  # pragma: no cover

    def brain(view):
        yield Call("read_note", {"name": "plan"})
        yield Delegate("c", "go", child)
        return "x"

    _run(brain)
    assert "notes" in seen["label"].conf


def test_parallel_children_run_and_budget_is_not_overshot():
    def child(view):
        out = []
        for _ in range(4):
            r = yield Call("list_notes")
            out.append(r.status)
        return ",".join(out)

    def brain(view):
        rs = yield Parallel(tuple(Delegate(f"w{i}", "go", child) for i in range(4)))
        return str(len(rs))

    s, res = _run(brain, {"type": "max_calls", "n": 7})
    ok = [e for e in s.journal.events("call_result") if e["data"]["status"] == "ok"]
    assert len(ok) == 7 and res.output == "4"  # 16 attempts across 4 threads, exactly 7 admitted


def test_step_limit_stops_a_runaway_agent():
    def brain(view):
        while True:
            yield Call("list_notes")

    s = build_stack()
    s.mesh.max_steps = 5
    res = s.mesh.run("t", brain, s.authority.mint("r"))
    assert res.status == "max_steps"


def test_agent_limit_and_brain_exceptions_are_contained():
    def boom(view):
        raise RuntimeError("bad brain")
        yield  # pragma: no cover

    s, res = _run(boom)
    assert res.status == "error" and "bad brain" in res.output

    def many(view):
        for i in range(10):
            yield Delegate(f"a{i}", "go", lambda v: "ok")
        return "x"

    s = build_stack()
    s.mesh.max_agents = 4
    s.mesh.run("t", many, s.authority.mint("r"))
    assert s.mesh.agents_started == 4


def test_invalid_delegation_caveat_is_refused_not_crashed():
    def brain(view):
        r = yield Delegate("c", "go", lambda v: "ok", ({"type": "bogus"},))
        return r.status

    assert _run(brain)[1].output == "refused"


def test_default_policy_decisions():
    s = build_stack()
    from agentmesh.broker import default_policy

    pol = default_policy()
    assert pol.evaluate(s.broker.registry.get("read_note")).action is Action.ALLOW
    assert pol.evaluate(s.broker.registry.get("send_email")).action is Action.ASK


def test_journal_of_a_run_is_intact_and_records_every_decision():
    def brain(view):
        yield Call("read_note", {"name": "plan"})
        yield Call("send_email", {"to": "x@evil.test", "subject": "s", "body": "b"})
        return "x"

    s, _ = _run(brain)
    assert s.journal.verify() == (True, None)
    kinds = {e["kind"] for e in s.journal.events()}
    assert {"agent_started", "call_requested", "decision", "call_result", "agent_finished"} <= kinds


def test_private_helper_builds_labels():
    assert private("a", "b") == Label(frozenset({"a", "b"}))
