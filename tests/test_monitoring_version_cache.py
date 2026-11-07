"""Version metadata is reused until the configured binary actually changes."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from test_next_stage import main


def test_repeated_and_concurrent_metadata_reads_spawn_once(tmp_path):
    binary = tmp_path / "fixture-core"
    binary.write_text("first binary", encoding="utf-8")
    result = SimpleNamespace(stdout="sing-box version fixture-v1\n", stderr="", returncode=0)
    with patch.object(main.config.singbox, "binary", str(binary)), \
         patch.object(main, "_core_version_cache", None), \
         patch.object(main.subprocess, "run", return_value=result) as run:
        with ThreadPoolExecutor(max_workers=8) as executor:
            assert list(executor.map(lambda _: main._singbox_version(), range(16))) == ["fixture-v1"] * 16
        assert run.call_count == 1


def test_binary_replacement_invalidates_and_missing_binary_is_retryable(tmp_path):
    binary = tmp_path / "fixture-core"
    binary.write_text("first", encoding="utf-8")
    responses = [SimpleNamespace(stdout="sing-box version v1\n", stderr=""),
                 SimpleNamespace(stdout="sing-box version v2\n", stderr="")]
    with patch.object(main.config.singbox, "binary", str(binary)), \
         patch.object(main, "_core_version_cache", None), \
         patch.object(main.subprocess, "run", side_effect=responses) as run:
        assert main._singbox_version() == "v1"
        replacement = tmp_path / "replacement"
        replacement.write_text("second binary", encoding="utf-8")
        replacement.replace(binary)
        assert main._singbox_version() == "v2"
        assert run.call_count == 2
    binary.unlink()
    with patch.object(main.config.singbox, "binary", str(binary)), \
         patch.object(main, "_core_version_cache", None), \
         patch.object(main.subprocess, "run", side_effect=FileNotFoundError) as run:
        assert main._singbox_version() == "unknown"
        assert main._singbox_version() == "unknown"
        assert run.call_count == 2
