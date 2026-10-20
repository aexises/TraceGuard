"""Optional supervision can withhold calls; deterministic authority remains mandatory."""

from traceguard.supervisor.base import Supervisor, merge_outputs

__all__ = ["Supervisor", "merge_outputs"]
