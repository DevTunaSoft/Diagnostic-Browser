from diagnostic_browser.profile_lock import lock_profile
import pytest

def test_single_instance_rejects_competing_profile(tmp_path):
    with lock_profile(tmp_path):
        with pytest.raises(RuntimeError, match='already in use'):
            with lock_profile(tmp_path):
                pass
    with lock_profile(tmp_path):
        pass

def test_lock_contains_no_user_data(tmp_path):
    # Read the lock file AFTER release: on Windows the held byte-range lock denies
    # reads of the locked region (PermissionError), and the sentinel content is
    # written once at acquisition and never changes, so reading post-release
    # verifies the identical bytes on every platform.
    with lock_profile(tmp_path):
        pass
    content = (tmp_path/'diagnostic_browser.instance.lock').read_text(errors='replace').strip()
    assert not content.startswith('http')
    assert content in ('', '0')
