import os
import sys

# Tests import the app as `mandacaru.src...`, so the repo's PARENT directory must be
# on sys.path regardless of where pytest is invoked from.
# (This file lives at <repo>/conftest.py, so we go up two levels: file -> repo root -> parent.)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
