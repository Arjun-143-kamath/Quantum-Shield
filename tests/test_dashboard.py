
import json

import pytest

import quantumshield.benchmark.dashboard as dashboard


def test_discover_benchmark_files(tmp_path, monkeypatch):

    monkeypatch.setattr(
        dashboard,
        "RESULTS_DIR",
        tmp_path
    )

    first = tmp_path / "benchmark_first.json"
    second = tmp_path / "benchmark_second.json"

    first.write_text("{}", encoding="utf-8")
    second.write_text("{}", encoding="utf-8")

    files = dashboard.get_benchmark_files()

    assert len(files) == 2
    assert first in files
    assert second in files


def test_load_valid_benchmark_report(tmp_path):

    report = {
        "metadata": {},
        "key_generation": {},
        "key_establishment": {},
        "digital_signatures": {},
        "file_encryption": [],
        "key_sizes": {}
    }

    report_path = tmp_path / "benchmark.json"

    report_path.write_text(
        json.dumps(report),
        encoding="utf-8"
    )

    loaded = dashboard.load_benchmark_report(report_path)

    assert loaded == report


def test_load_invalid_benchmark_report(tmp_path):

    report_path = tmp_path / "invalid.json"

    report_path.write_text(
        json.dumps({"metadata": {}}),
        encoding="utf-8"
    )

    with pytest.raises(ValueError):

        dashboard.load_benchmark_report(report_path)


def test_load_malformed_json(tmp_path):

    report_path = tmp_path / "broken.json"

    report_path.write_text(
        "{ invalid json",
        encoding="utf-8"
    )

    with pytest.raises(ValueError):

        dashboard.load_benchmark_report(report_path)

