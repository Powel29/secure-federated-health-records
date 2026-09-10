"""Federated Break-Glass EHR Demo Package (P4-5, ARCHITECTURE.md §6, PROJECT.md D2).

Contains synthetic patient datasets and interactive, examiner-ready demo drivers.
"""

from __future__ import annotations

from demo.driver import run_demo_scenario
from demo.seed_data import create_synthetic_dataset, seed_synthetic_data

__all__ = [
    "create_synthetic_dataset",
    "seed_synthetic_data",
    "run_demo_scenario",
]
