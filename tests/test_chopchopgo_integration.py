import json
import os
import stat
import subprocess
import urllib.request
import zipfile
from pathlib import Path

import pytest

RELEASE_URL = (
    "https://github.com/M00NLIG7/ChopChopGo/releases/download/"
    "v1.0.0-release-1/v1.0.0-release-1.zip"
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Expected Sigma rule IDs for sanity checks
EXPECTED_DETECTIONS = {
    "syslog_chopchopgo_trigger.log": "e09eb557-96d2-4de9-ba2d-30f712a5afd3",
    "syslog_chopchopgo_wget_chmod.log": "2aa1440c-9ae9-4d92-84a7-a9e5f5e31695",
    "syslog_chopchopgo_reverse_shell.log": "738d9bcf-6999-4fdb-b4ac-3033037db8ab",
    "syslog_chopchopgo_promisc.log": "f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1",
}


def _download_release(dest: Path) -> Path:
    archive_path = dest / "chopchopgo.zip"
    if not archive_path.exists():
        with urllib.request.urlopen(RELEASE_URL) as response, open(archive_path, "wb") as fh:
            fh.write(response.read())

    extract_root = dest / "release"
    if not extract_root.exists():
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_root)

    binary_path = extract_root / "ChopChopGo" / "ChopChopGo"
    binary_mode = binary_path.stat().st_mode
    binary_path.chmod(binary_mode | stat.S_IXUSR)
    return binary_path


@pytest.fixture(scope="session")
def chopchopgo_bundle(tmp_path_factory):
    cache_root = Path(
        os.environ.get("CHOPCHOPGO_TEST_CACHE", str(tmp_path_factory.mktemp("chopchopgo")))
    )
    binary = _download_release(cache_root)
    rules_dir = cache_root / "release" / "ChopChopGo" / "rules" / "linux" / "builtin"
    return binary, rules_dir


@pytest.mark.parametrize("fixture_name", sorted(EXPECTED_DETECTIONS))
def test_chopchopgo_hits_expected_rules(chopchopgo_bundle, fixture_name):
    binary, rules_dir = chopchopgo_bundle
    log_path = FIXTURES / fixture_name
    assert log_path.exists(), log_path

    command = [
        str(binary),
        "-target",
        "syslog",
        "-rules",
        str(rules_dir),
        "-file",
        str(log_path),
        "-out",
        "json",
    ]

    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    stdout = completed.stdout.strip() or "null"
    parsed = json.loads(stdout)

    assert parsed, f"Expected detections for {fixture_name}, got {stdout!r}"
    expected_rule_id = EXPECTED_DETECTIONS[fixture_name]
    assert any(entry.get("ID") == expected_rule_id for entry in parsed), (
        f"Rule {expected_rule_id} not triggered for {fixture_name}; output={stdout!r}"
    )
