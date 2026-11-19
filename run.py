#!/usr/bin/env python3
"""Entry point.

    python run.py all --approve-writes      # the whole loop
    python run.py inventory                 # discovery + zombie/shadow only
    python run.py guard-demo                # prove the safety layer refuses
    python run.py retest                    # replay stored proofs, auto-close fixes
    python run.py catalogue                 # the test library

Standard library only -- no pip install required for the harness or the mock target.
"""

import sys

from dast.cli import main

if __name__ == "__main__":
    sys.exit(main())
