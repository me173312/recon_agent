"""
Coverage module for tracking tested vulnerabilities and scan histories.
"""

from .coverage import (
    initialize_database,
    mark_tested,
    get_untested,
    add_scan_snapshot,
)

__all__ = [
    "initialize_database",
    "mark_tested",
    "get_untested",
    "add_scan_snapshot",
]
