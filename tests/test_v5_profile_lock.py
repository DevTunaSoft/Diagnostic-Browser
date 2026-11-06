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
    with lock_profile(tmp_path):
        assert not (tmp_path/'diagnostic_browser.instance.lock').read_text(errors='replace').strip().startswith('http')
