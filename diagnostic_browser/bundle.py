"""Self-contained frozen runtime resolution, with no runtime downloads.

The EXE is the application and worker launcher; the bootloader may extract
signed/bundled resources at runtime. Persistent evidence stays in LOCALAPPDATA.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

MODEL_NAME = 'SmolLM2-135M-Instruct-Q4_K_M.gguf'
MODEL_SHA256 = '8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684'


def is_frozen() -> bool:
    return bool(getattr(sys, 'frozen', False))


def bundle_root() -> Path:
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])).resolve()


def model_path() -> Path:
    return bundle_root() / 'models' / MODEL_NAME


def configure_bundled_browser() -> None:
    """Playwright looks for bundled .local-browsers, not a user cache/install."""
    if is_frozen():
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = '0'


def bundled_browser_path() -> Path | None:
    """Resolve only the Chromium installed into Playwright's bundled location."""
    if not is_frozen():
        return None
    configure_bundled_browser()
    from playwright._impl._driver import compute_driver_executable
    driver, _ = compute_driver_executable()
    root = Path(driver).resolve().parent / 'package' / '.local-browsers'
    # Playwright performs final executable lookup and revision checking; don't
    # infer a revision or silently fall back to an installed Chrome.
    if not root.is_dir() or not any(root.iterdir()):
        raise RuntimeError('Bundled Chromium is missing; standalone build is incomplete')
    return root


def verify_bundled_runtime() -> dict:
    """Fail closed if the single-file release lost a mandatory payload."""
    if not is_frozen():
        return {'packaging': 'SOURCE', 'verified': False}
    from . import VERSION
    browser = bundled_browser_path()
    model = model_path()
    if not model.is_file() or model.stat().st_size < 1024 * 1024:
        raise RuntimeError('Bundled offline AI model is missing or invalid')
    import hashlib
    h = hashlib.sha256()
    with model.open('rb') as binary:
        for chunk in iter(lambda: binary.read(1024*1024), b''):
            h.update(chunk)
    if h.hexdigest() != MODEL_SHA256:
        raise RuntimeError('Bundled offline AI model failed SHA-256 verification')
    import llama_cpp  # noqa: F401 - fail closed on missing CPU inference runtime
    if not (Path(__file__).parent / 'static' / 'index.html').is_file():
        raise RuntimeError('Bundled dashboard is missing')
    return {'packaging': 'ONE_FILE', 'verified': True, 'version': VERSION,
            'embedded_chromium': True, 'offline_ai_model': True,
            'model_bytes': model.stat().st_size}
