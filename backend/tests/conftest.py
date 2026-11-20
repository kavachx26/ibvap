"""Every test run gets its own empty data directory (database, snapshots,
signing key), so tests never touch the real demo database."""
import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="ibvap-test-")
os.environ["IBVAP_DATA_DIR"] = _TMP
os.environ["IBVAP_DETECTOR"] = "hog"          # tests never load YOLO weights
os.environ["IBVAP_CHECKPOINT_EVERY"] = "10"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
