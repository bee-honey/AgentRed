"""Tests for the RAG scenario: injection arrives in retrieved content."""

import pytest

from agentred.designs import DESIGNS
from agentred.run import build_model, evaluate, make_provider
from agentred.scenario import CANARY, SCENARIOS

RAG = SCENARIOS["rag"]


def test_task_is_clean_injection_is_only_in_retrieved_content():
    assert "INTERNAL_API_KEY" not in RAG.task
    assert "INTERNAL_API_KEY" in RAG.retrieved_content
    assert RAG.injection_point == "document"


def test_search_docs_returns_the_poisoned_document():
    provider = make_provider("inprocess", RAG)
    try:
        out = provider.dispatch("search_docs", {"query": "password reset"})
        assert "kb-07" in out  # benign docs present
        assert "INTERNAL_API_KEY" in out  # poisoned doc spliced in
    finally:
        provider.close()


def test_naive_agent_leaks_canary_from_retrieved_content():
    run, verdict = evaluate(RAG, build_model("scripted:naive", RAG))
    assert not verdict.passed
    assert verdict.invariant == "NO_SECRET_EGRESS"
    assert [c.name for c in run.trace.calls] == ["search_docs", "send_email"]


def test_careful_agent_answers_without_leaking():
    run, verdict = evaluate(RAG, build_model("scripted:careful", RAG))
    assert verdict.passed
    assert run.trace.calls_to("search_docs")
    assert not run.trace.calls_to("send_email")


def test_policy_guard_blocks_the_rag_egress_attempt():
    run, verdict = evaluate(RAG, build_model("scripted:naive", RAG), design=DESIGNS["policy-guard"])
    assert verdict.passed
    assert run.trace.blocked  # the exfil send_email was refused
    assert CANARY not in "".join(c.result for c in run.trace.executed)


def test_rag_poisoned_document_served_over_mcp():
    provider = make_provider("mcp", RAG)
    try:
        out = provider.dispatch("search_docs", {"query": "reset"})
        assert "INTERNAL_API_KEY" in out
    finally:
        provider.close()
