import sqlite3

from agentmesh.journal import Journal


def test_chain_verifies_and_survives_reopen(tmp_path):
    path = str(tmp_path / "j.db")
    j = Journal(path)
    for i in range(5):
        j.append("e", {"i": i})
    j.close()
    again = Journal(path)
    again.append("e", {"i": 5})
    assert again.verify() == (True, None) and len(again.events()) == 6


def test_editing_an_event_is_detected(tmp_path):
    path = str(tmp_path / "j.db")
    j = Journal(path)
    for i in range(4):
        j.append("e", {"i": i})
    j.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE events SET data = '{\"i\":99}' WHERE seq = 2")
    db.commit()
    db.close()
    assert Journal(path).verify() == (False, 2)


def test_deleting_a_middle_event_is_detected(tmp_path):
    path = str(tmp_path / "j.db")
    j = Journal(path)
    for i in range(4):
        j.append("e", {"i": i})
    j.close()
    db = sqlite3.connect(path)
    db.execute("DELETE FROM events WHERE seq = 2")
    db.commit()
    db.close()
    ok, bad = Journal(path).verify()
    assert not ok and bad == 3


def test_filtering_by_kind():
    j = Journal()
    j.append("a", {})
    j.append("b", {})
    assert [e["kind"] for e in j.events("b")] == ["b"]
