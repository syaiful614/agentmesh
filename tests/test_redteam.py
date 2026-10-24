import pytest

from agentmesh import cli
from agentmesh.redteam import run_all, run_scenario, scenarios

BY_NAME = {s.name: s for s in scenarios()}


def test_every_attack_is_contained():
    failed = [r for r in run_all() if not r.passed]
    assert not failed, failed


def test_there_are_twelve_scenarios_with_unique_names():
    assert len(BY_NAME) == 12 == len(scenarios())


# Mutation tests: switch one defence off and the matching attack must succeed. If it does not, the
# scenario was passing for the wrong reason.
@pytest.mark.parametrize("name", ["direct_exfil", "parallel_siblings_are_joined"])
def test_without_the_flow_check_the_leak_happens(name):
    assert not run_scenario(BY_NAME[name], flow=False).passed


@pytest.mark.parametrize(
    "name",
    ["laundering_via_subagent_result", "laundering_via_task_text", "parallel_siblings_are_joined"],
)
def test_without_label_propagation_laundering_works(name):
    assert not run_scenario(BY_NAME[name], propagate=False).passed


def test_cli_redteam_exit_code_and_journals(tmp_path, capsys):
    assert cli.main(["redteam", "--journal-dir", str(tmp_path)]) == 0
    assert "12/12 attack scenarios contained" in capsys.readouterr().out
    db = str(tmp_path / "laundering_via_task_text.db")
    assert cli.main(["verify", db]) == 0
    assert cli.main(["show", db]) == 0
    assert "decision" in capsys.readouterr().out


def test_cli_verify_reports_tampering(tmp_path, capsys):
    import sqlite3

    cli.main(["redteam", "--journal-dir", str(tmp_path)])
    db = str(tmp_path / "direct_exfil.db")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET data = '{}' WHERE seq = 3")
    conn.commit()
    conn.close()
    capsys.readouterr()
    assert cli.main(["verify", db]) == 1
    assert "TAMPERED at event 3" in capsys.readouterr().out
