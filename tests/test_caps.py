import pytest

from agentmesh.caps import Authority, CapabilityError, Token, evaluate, remaining_depth

KEY = b"0123456789abcdef-test-key"


def _eval(token, auth, tool="read_note", args=None, sink=False, now=0.0, counts=None):
    chain = auth.verify(token)
    return evaluate(token.caveats, chain, tool, args or {}, is_sink=sink, now=now, counts=counts or {})


def test_minted_and_attenuated_tokens_verify():
    auth = Authority(KEY)
    root = auth.mint("t1", {"type": "tools", "allow": ["read_*"]})
    child = root.attenuate({"type": "no_sinks"})
    assert auth.verify(root) and len(auth.verify(child)) == 2


def test_removing_a_caveat_breaks_the_signature():
    auth = Authority(KEY)
    child = auth.mint("t1", {"type": "tools", "allow": ["read_*"]}).attenuate({"type": "no_sinks"})
    with pytest.raises(CapabilityError, match="signature"):
        auth.verify(Token(child.id, child.caveats[:1], child.sig))


def test_editing_a_caveat_breaks_the_signature():
    auth = Authority(KEY)
    tok = auth.mint("t1", {"type": "tools", "allow": ["read_*"]})
    forged = Token(tok.id, ({"type": "tools", "allow": ["*"]},), tok.sig)
    with pytest.raises(CapabilityError):
        auth.verify(forged)


def test_a_token_from_another_authority_is_rejected():
    tok = Authority(b"another-key-1234567890").mint("t1")
    with pytest.raises(CapabilityError):
        Authority(KEY).verify(tok)


def test_encode_decode_roundtrip_and_garbage():
    auth = Authority(KEY)
    tok = auth.mint("t1", {"type": "max_calls", "n": 2})
    assert auth.verify(Token.decode(tok.encode()))
    with pytest.raises(CapabilityError):
        Token.decode("not-a-token")


@pytest.mark.parametrize(
    "bad",
    [
        {"type": "nope"},
        {"type": "tools", "allow": []},
        {"type": "args", "tool": "x", "arg": "y", "regex": "("},
        {"type": "max_calls", "n": -1},
        {"type": "depth", "remaining": True},
        {"type": "expires", "at": "soon"},
    ],
)
def test_invalid_caveats_are_refused(bad):
    with pytest.raises(CapabilityError):
        Authority(KEY).mint("t1", bad)


def test_short_root_key_is_refused():
    with pytest.raises(CapabilityError):
        Authority(b"short")


def test_tool_scope_is_an_intersection():
    auth = Authority(KEY)
    tok = auth.mint("t", {"type": "tools", "allow": ["read_*", "send_*"]}).attenuate(
        {"type": "tools", "allow": ["read_*"]}
    )
    assert _eval(tok, auth, "read_note").ok
    assert not _eval(tok, auth, "send_email").ok


def test_arg_constraint_fails_closed_on_missing_argument():
    auth = Authority(KEY)
    tok = auth.mint("t", {"type": "args", "tool": "send_email", "arg": "to", "regex": r"@example\.com$"})
    assert _eval(tok, auth, "send_email", {"to": "a@example.com"}).ok
    assert not _eval(tok, auth, "send_email", {"to": "a@evil.test"}).ok
    assert not _eval(tok, auth, "send_email", {}).ok
    assert _eval(tok, auth, "read_note", {}).ok  # other tools are unaffected


def test_expiry_and_no_sinks_and_budget():
    auth = Authority(KEY)
    assert not _eval(auth.mint("t", {"type": "expires", "at": 10}), auth, now=10).ok
    assert _eval(auth.mint("t", {"type": "expires", "at": 10}), auth, now=9).ok
    nosink = auth.mint("t", {"type": "no_sinks"})
    assert not _eval(nosink, auth, "send_email", sink=True).ok and _eval(nosink, auth).ok
    capped = auth.mint("t", {"type": "max_calls", "n": 1})
    chain = auth.verify(capped)
    assert _eval(capped, auth, counts={chain[0]: 0}).ok
    assert not _eval(capped, auth, counts={chain[0]: 1}).ok


def test_remaining_depth_is_the_minimum():
    auth = Authority(KEY)
    assert remaining_depth(auth.mint("t").caveats) is None
    tok = auth.mint("t", {"type": "depth", "remaining": 3}).attenuate({"type": "depth", "remaining": 1})
    assert remaining_depth(tok.caveats) == 1
