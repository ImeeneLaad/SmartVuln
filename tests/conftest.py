import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIX


@pytest.fixture
def semgrep_report() -> dict:
    return json.loads((FIX / "semgrep_sample.json").read_text())


@pytest.fixture
def zap_report() -> dict:
    return json.loads((FIX / "zap_sample.json").read_text())


@pytest.fixture
def trivy_report() -> dict:
    return json.loads((FIX / "trivy_sample.json").read_text())
