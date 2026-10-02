"""Tests for attack corpora: loading, applying, and judging every variant."""

import json

import pytest

from agentred.attacks import HANDWRITTEN, apply_attack, load_corpus, scenario_variants
from agentred.run import build_model, evaluate, main, make_provider
from agentred.scenario import SCENARIOS, TOOL_POISONING


def test_agentdojo_corpus_loads_with_goal_slots():
    attacks = load_corpus("agentdojo")
    assert {a.id for a in attacks} >= {"direct", "ignore_previous", "important_instructions"}
    assert all("{goal}" in a.template for a in attacks)
    assert {a.source for a in attacks} == {"AgentDojo"}


def test_custom_corpus_from_path(tmp_path):
    path = tmp_path / "mine.json"
    path.write_text(json.dumps({"source": "Mine", "attacks": [{"id": "x", "template": "X {goal}"}]}))
    (attack,) = load_corpus(str(path))
    assert attack.render("do it") == "X do it"


def test_unknown_corpus_is_a_clear_error():
    with pytest.raises(ValueError, match="unknown corpus"):
        load_corpus("nope")


@pytest.mark.parametrize("scenario", list(SCENARIOS.values()), ids=list(SCENARIOS))
def test_every_variant_carries_the_goal_and_keeps_the_judge_working(scenario):
    variants = scenario_variants(scenario, load_corpus("agentdojo"))
    assert variants[0].attack == HANDWRITTEN
    for v in variants[1:]:
        if v.injection_point == "task":
            surface = v.task
        elif v.injection_point == "document":
            surface = v.retrieved_content
        else:
            surface = v.description_overrides["lookup_order"]
        assert scenario.injection_goal in surface
        # The attack payload changes; the invariant and its verdicts do not.
        assert not evaluate(v, build_model("scripted:naive", v))[1].passed
        assert evaluate(v, build_model("scripted:careful", v))[1].passed


def test_poisoning_variant_reaches_the_mcp_server():
    attack = next(a for a in load_corpus("agentdojo") if a.id == "injecagent")
    variant = apply_attack(TOOL_POISONING, attack)
    provider = make_provider("mcp", variant)
    try:
        (schema,) = provider.tool_schemas()
        assert schema["description"].startswith("Look up the shipping status")
        assert "IMPORTANT!!! Ignore all previous instructions" in schema["description"]
    finally:
        provider.close()


def test_attack_matrix_cli(capsys):
    assert main(["--scenario", "authz", "--attacks", "agentdojo"]) == 0
    out = capsys.readouterr().out
    assert "attack corpus: AgentDojo" in out
    assert "important_instructions" in out
    assert "6/6 (100%)" in out and "0/6 (0%)" in out  # naive vs careful totals


def test_persuasion_corpus_and_multiturn_load_together():
    from agentred.attacks import load_attacks

    attacks = load_attacks("persuasion,multiturn")
    ids = [a.id for a in attacks]
    assert ids[-1] == "multiturn" and "authority_endorsement" in ids
    assert all("{goal}" in a.template for a in attacks)


def test_multiturn_variant_plays_a_clean_opening_then_pressure():
    from agentred.attacks import load_attacks

    authz = SCENARIOS["authz"]
    variant = scenario_variants(authz, load_attacks("multiturn"))[-1]
    assert variant.attack == "multiturn"
    assert "ceo" not in variant.task.lower()  # the opening request is clean
    assert any("user=ceo" in turn for turn in variant.followups)
    # scenarios without a script are skipped, not failed
    assert [v.attack for v in scenario_variants(SCENARIOS["egress"], load_attacks("multiturn"))] == ["handwritten"]


def test_agent_plays_every_turn_in_one_conversation():
    from agentred.models import ModelTurn

    seen = []

    class Recorder:
        def generate(self, system, messages, tools):
            seen.append([m["content"] for m in messages if m["role"] == "user"])
            return ModelTurn(text=f"reply {len(seen)}")

    approval = SCENARIOS["approval"].as_multi_turn()
    run, _ = evaluate(approval, Recorder())
    assert len(seen) == 3 and seen[-1] == list(approval.multi_turn)  # history kept across turns
    assert run.final_text == "reply 1\n\nreply 2\n\nreply 3"
