"""Statistics used in reports. Pure functions, no dependencies beyond the stdlib.

With 50 attacks per configuration, point estimates alone overstate certainty, so every
rate is reported with a Wilson 95% interval, and defence comparisons use an exact
McNemar test on the paired outcomes (same attacks, different defence).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass(frozen=True)
class Rate:
    k: int
    n: int

    @property
    def value(self) -> float:
        return self.k / self.n if self.n else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        return wilson(self.k, self.n)

    def fmt(self) -> str:
        lo, hi = self.ci
        return f"{self.value:.0%} [{lo:.0%}–{hi:.0%}] ({self.k}/{self.n})"

    def as_dict(self) -> dict:
        lo, hi = self.ci
        return {"k": self.k, "n": self.n, "rate": round(self.value, 4),
                "ci95": [round(lo, 4), round(hi, 4)]}  # fmt: skip


@dataclass(frozen=True)
class Agreement:
    n: int
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def kappa(self) -> float:
        """Cohen's kappa: agreement corrected for chance."""
        n = self.n
        if n == 0:
            return 0.0
        po = (self.tp + self.tn) / n
        p_yes = ((self.tp + self.fp) / n) * ((self.tp + self.fn) / n)
        p_no = ((self.fn + self.tn) / n) * ((self.fp + self.tn) / n)
        pe = p_yes + p_no
        return 1.0 if pe == 1 else (po - pe) / (1 - pe)

    def as_dict(self) -> dict:
        return {
            "n": self.n, "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "accuracy": round(self.accuracy, 4), "precision": round(self.precision, 4),
            "recall": round(self.recall, 4), "f1": round(self.f1, 4),
            "kappa": round(self.kappa, 4),
        }  # fmt: skip


def agreement(predicted: Sequence[bool], gold: Sequence[bool]) -> Agreement:
    if len(predicted) != len(gold):
        raise ValueError("predicted and gold must be the same length")
    tp = sum(p and g for p, g in zip(predicted, gold, strict=True))
    fp = sum(p and not g for p, g in zip(predicted, gold, strict=True))
    fn = sum(g and not p for p, g in zip(predicted, gold, strict=True))
    tn = sum(not p and not g for p, g in zip(predicted, gold, strict=True))
    return Agreement(len(gold), tp, fp, fn, tn)


def mcnemar_exact(baseline: Sequence[bool], treated: Sequence[bool]) -> dict:
    """Exact two-sided McNemar test on paired binary outcomes.

    ``b`` = cases that failed under baseline but not treated (fixed by the defence);
    ``c`` = cases that passed under baseline but failed under treated (regressions).
    """
    b = sum(x and not y for x, y in zip(baseline, treated, strict=True))
    c = sum(y and not x for x, y in zip(baseline, treated, strict=True))
    n = b + c
    if n == 0:
        return {"fixed": 0, "regressed": 0, "p_value": 1.0}
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / 2**n
    return {"fixed": b, "regressed": c, "p_value": round(min(1.0, 2 * tail), 6)}


def interpret_kappa(k: float) -> str:
    """Landis & Koch (1977) bands."""
    for bound, label in [(0.8, "almost perfect"), (0.6, "substantial"), (0.4, "moderate"),
                         (0.2, "fair"), (0.0, "slight")]:  # fmt: skip
        if k > bound:
            return label
    return "poor"
