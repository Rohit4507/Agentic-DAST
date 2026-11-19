"""Test library. Each attack performs requests and returns a verified Finding or None.

Naming note: these are *attack implementations*, not unit tests -- the unit tests live
in ``tests/``. The plan document called this directory ``tests/``; ``attacks/`` avoids
the collision.
"""

from .bola import test_cross_tenant_read  # noqa: F401
from .logic import test_double_refund, test_fare_tampering, test_skipped_payment  # noqa: F401
from .registry import TESTS, get_test  # noqa: F401
