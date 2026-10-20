"""The enclave signs only what it built itself.

get_attestation attests the public key of an enclave session and never caller-chosen user_data;
researcher scripts run as SCRIPT_UID, not as the root process that holds /dev/nsm.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from config import SCRIPT_GID, SCRIPT_UID
from implementations import execute_service_impl
from implementations.request_handler_impl import RequestHandlerImpl


@pytest.fixture
def handler():
    keypairs = MagicMock()
    keypairs.get_public_key.side_effect = lambda sid: 'PEM-KEY' if sid == 'session_1' else None
    attestation = MagicMock()
    attestation.generate_attestation.return_value = (True, {'attestation_document': 'DOC'})
    attestation.is_real_enclave = True
    return RequestHandlerImpl(MagicMock(), MagicMock(), keypairs, attestation), attestation


class TestGetAttestation:
    def test_attests_the_session_key_built_by_the_enclave(self, handler):
        h, attestation = handler
        resp = h.handle_request(json.dumps({'operation': 'get_attestation', 'session_id': 'session_1'}))

        assert resp['success'] is True
        user_data = attestation.generate_attestation.call_args.kwargs['user_data']
        assert json.loads(user_data) == {'public_key': 'PEM-KEY', 'session_id': 'session_1'}

    def test_caller_user_data_is_refused(self, handler):
        h, attestation = handler
        resp = h.handle_request(json.dumps({
            'operation': 'get_attestation', 'session_id': 'session_1',
            'user_data': json.dumps({'public_key': 'HOST-KEY'}),
        }))

        assert resp['success'] is False
        attestation.generate_attestation.assert_not_called()

    @pytest.mark.parametrize('request_body', [
        {'operation': 'get_attestation'},
        {'operation': 'get_attestation', 'session_id': 'unknown'},
    ], ids=['no-session', 'unknown-session'])
    def test_nothing_is_signed_without_an_enclave_session(self, handler, request_body):
        h, attestation = handler
        resp = h.handle_request(json.dumps(request_body))

        assert resp['success'] is False
        attestation.generate_attestation.assert_not_called()


class TestScriptUser:
    def test_unprivileged_process_runs_scripts_as_is(self, tmp_path):
        with patch.object(execute_service_impl.os, 'geteuid', return_value=1000):
            assert execute_service_impl._as_script_user(str(tmp_path)) == {}

    def test_root_hands_the_work_dir_over_and_drops_privileges(self, tmp_path):
        (tmp_path / 'outputs').mkdir()
        (tmp_path / 'main.py').write_text('print(1)')
        with patch.object(execute_service_impl.os, 'geteuid', return_value=0), \
                patch.object(execute_service_impl.os, 'chown') as chown:
            kwargs = execute_service_impl._as_script_user(str(tmp_path))

        assert kwargs == {'preexec_fn': execute_service_impl._drop_privileges}
        owned = {c.args[0] for c in chown.call_args_list}
        assert owned == {str(tmp_path), str(tmp_path / 'outputs'), str(tmp_path / 'main.py')}
        assert all(c.args[1:] == (SCRIPT_UID, SCRIPT_GID) for c in chown.call_args_list)

    def test_drop_privileges_clears_groups_then_gid_then_uid(self):
        calls = MagicMock()
        with patch.object(execute_service_impl.os, 'setgroups', calls.setgroups), \
                patch.object(execute_service_impl.os, 'setgid', calls.setgid), \
                patch.object(execute_service_impl.os, 'setuid', calls.setuid):
            execute_service_impl._drop_privileges()

        assert [c[0] for c in calls.mock_calls] == ['setgroups', 'setgid', 'setuid']
        calls.setuid.assert_called_once_with(SCRIPT_UID)


class TestValidateScript:
    @pytest.mark.parametrize('script', [
        'import sklearn\nimport seaborn as sns\nfrom imblearn.over_sampling import SMOTE\n',
        'import time, warnings, traceback\n',
        'from src.models import train\n',
        'import re\npattern = re.compile("x")\nmodel.compile(optimizer="adam")\n',
    ], ids=['analysis-packages', 'stdlib', 'local-module', 'compile-methods'])
    def test_imports_and_method_calls_are_allowed(self, script):
        ok, msg = execute_service_impl.ExecuteServiceImpl(None).validate_script(script)
        assert ok, msg

    @pytest.mark.parametrize('script', ['exec("x")\n', 'eval("1")\n', '__import__("os")\n', 'x = (\n'])
    def test_builtin_dynamic_code_and_bad_syntax_are_refused(self, script):
        ok, _ = execute_service_impl.ExecuteServiceImpl(None).validate_script(script)
        assert not ok
