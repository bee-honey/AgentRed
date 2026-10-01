"""Tests for the small-sample statistics, checked against textbook values."""

import pytest

from agentred.run import main
from agentred.stats import fisher_exact, format_rate, pairwise_lines, wilson_interval


def test_fisher_exact_matches_reference_values():
    assert fisher_exact(3, 4, 1, 4) == pytest.approx(0.4857, abs=1e-4)  # lady tasting tea
    assert fisher_exact(1, 10, 11, 14) == pytest.approx(0.002759, abs=1e-6)
    assert fisher_exact(2, 3, 2, 3) == pytest.approx(1.0)


def test_wilson_interval_matches_reference_values_and_stays_in_bounds():
    assert wilson_interval(0, 10) == pytest.approx((0.0, 0.2775), abs=1e-4)
    assert wilson_interval(81, 263) == pytest.approx((0.2553, 0.3662), abs=1e-4)
    lo, hi = wilson_interval(3, 3)
    assert 0 < lo < 1 and hi == 1.0


def test_format_rate():
    assert format_rate(3, 18) == "3/18 (17%, 95% CI 6%–39%)"


def test_pairwise_lines_skip_scripted_targets_and_flag_real_differences():
    lines = pairwise_lines([("scripted:naive", 18, 18), ("openai:a", 0, 18), ("openai:b", 14, 18)])
    assert len(lines) == 1
    assert "openai:a vs openai:b: p<0.001 — differ" in lines[0]
    (same,) = pairwise_lines([("x:a", 1, 3), ("x:b", 1, 3)])
    assert "no significant difference" in same


def test_comparison_table_shows_confidence_interval(capsys):
    main(["--scenario", "authz", "--compare", "scripted:naive,scripted:careful", "--trials", "3"])
    out = capsys.readouterr().out
    assert "95% CI" in out
    naive = next(line.split() for line in out.splitlines() if line.startswith("scripted:naive"))
    assert naive == ["scripted:naive", "3", "3", "100%", "44%–100%"]
