"""Small-sample statistics for violation rates (stdlib only).

Violation rates come from a handful of trials, so a bare "33%" overstates what
we know. Two tools keep the numbers honest:

  wilson_interval — a 95% confidence interval for one rate. Unlike the normal
                    approximation it stays inside [0, 1] and behaves at 0/n and
                    n/n, which is exactly where agent results tend to sit.
  fisher_exact    — a two-sided p-value for "do these two targets really differ?"
                    computed exactly from the hypergeometric distribution, so it
                    is valid at the tiny counts we have.
"""

from __future__ import annotations

from math import comb, sqrt

Z_95 = 1.959964


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def fisher_exact(k1: int, n1: int, k2: int, n2: int) -> float:
    """Two-sided Fisher's exact test p-value for k1/n1 vs k2/n2."""
    total_k, total_n = k1 + k2, n1 + n2

    def prob(a: int) -> float:  # P(first group has a of the total_k violations)
        return comb(n1, a) * comb(n2, total_k - a) / comb(total_n, total_k)

    observed = prob(k1)
    lo, hi = max(0, total_k - n2), min(total_k, n1)
    p = sum(q for a in range(lo, hi + 1) if (q := prob(a)) <= observed * (1 + 1e-7))
    return min(1.0, p)


def format_rate(k: int, n: int) -> str:
    """'3/18 (17%, 95% CI 6–39%)'."""
    if n == 0:
        return "—"
    lo, hi = wilson_interval(k, n)
    return f"{k}/{n} ({k / n:.0%}, 95% CI {lo:.0%}–{hi:.0%})"


def format_ci(k: int, n: int) -> str:
    """'6–39%'."""
    lo, hi = wilson_interval(k, n)
    return f"{lo:.0%}–{hi:.0%}"


def format_p(p: float) -> str:
    return "p<0.001" if p < 0.001 else f"p={p:.3f}"


def pairwise_lines(counts: list[tuple[str, int, int]]) -> list[str]:
    """Fisher's exact test between every pair of real (non-scripted) targets."""
    real = [c for c in counts if not c[0].startswith("scripted:") and c[2]]
    lines = []
    for i, (a, ka, na) in enumerate(real):
        for b, kb, nb in real[i + 1 :]:
            p = fisher_exact(ka, na, kb, nb)
            verdict = "differ" if p < 0.05 else "no significant difference"
            lines.append(f"  {a} vs {b}: {format_p(p)} — {verdict} (Fisher's exact, two-sided)")
    return lines
