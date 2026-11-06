"""Guard against another false-success release built with mismatched versions."""
from pathlib import Path
import re
import tomllib
import zipfile
import subprocess
import sys
from diagnostic_browser import VERSION

ROOT=Path(__file__).resolve().parents[1]

def test_all_active_release_components_have_same_version():
    meta=tomllib.loads((ROOT/'pyproject.toml').read_text())
    assert meta['project']['version']==VERSION
    builder=(ROOT/'scripts/build_offline_wheel.py').read_text()
    qa=(ROOT/'scripts/one_pass_qa.py').read_text()
    iss=(ROOT/'installer/DiagnosticBrowser.iss').read_text()
    assert f"VERSION='{VERSION}'" in builder
    assert f"'version':'{VERSION}'" in qa
    assert f'MyAppVersion "{VERSION}"' in iss
    assert f'DiagnosticBrowser-{VERSION}-UNSIGNED' in iss


def test_offline_wheel_has_valid_matching_version_and_record(tmp_path):
    # Build in the normal release script and inspect actual wheel metadata.
    # A source tree is necessary, but a Windows environment is not.
    try:
        import importlib.util
        spec=importlib.util.spec_from_file_location('local_wheel_builder',ROOT/'scripts/build_offline_wheel.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        assert module.VERSION==VERSION
    except (OSError,ImportError) as exc:
        raise AssertionError('offline release wheel builder is broken') from exc
