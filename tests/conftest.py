import os
import sys
import tempfile

# Isolate test data from the real ~/.paashaa and make the package importable
os.environ.setdefault("PAASHAA_HOME", tempfile.mkdtemp(prefix="paashaa-test-"))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
