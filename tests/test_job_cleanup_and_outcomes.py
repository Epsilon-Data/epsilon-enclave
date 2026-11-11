"""Every run leaves nothing behind and gets a signed record, whatever its outcome.

Scripts of all jobs share SCRIPT_UID: one runs at a time, and its processes and temp files are
removed before the next starts. A run that fails is signed with its outcome and the hash of its
error text, and the record carries the platform's job and attempt identifiers.
"""
import hashlib
import io
import json
import os
import signal
import subprocess
import time
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from implementations import execute_service_impl
from implementations.attestation_service_impl import AttestationService, MAX_USER_DATA_BYTES
from implementations.execute_service_impl import ExecuteServiceImpl
from implementations.request_handler_impl import RequestHandlerImpl
from interfaces.execute_interface import (
    BundleResult, OUTCOME_FAILED, OUTCOME_INVALID_BUNDLE, OUTCOME_SUCCEEDED, OUTCOME_TIMED_OUT,
)

EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
EMPTY_MANIFEST_SHA256 = hashlib.sha256(b'[]').hexdigest()


def _bundle(script):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('main.py', script)
    return buf.getvalue()


def _is_running(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_until_gone(pid, seconds=5.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not _is_running(pid):
            return True
        time.sleep(0.05)
    return False


SPAWN_SLEEPER = (
    "import subprocess\n"
    "p = subprocess.Popen(['sleep', '300'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    "print(p.pid)\n"
)


class TestCleanupAfterRun:
    def test_background_process_is_killed_when_the_script_exits(self):
        result = ExecuteServiceImpl(None).execute_bundle(_bundle(SPAWN_SLEEPER), 's1')
        assert result.success is True
        pid = int(result.output.strip())
        try:
            assert _wait_until_gone(pid)
        finally:
            if _is_running(pid):
                os.kill(pid, signal.SIGKILL)

    def test_background_process_is_killed_on_timeout(self):
        svc = ExecuteServiceImpl(None)
        svc._execution_limits['max_execution_time_seconds'] = 2
        script = (
            "import os, subprocess, time\n"
            "p = subprocess.Popen(['sleep', '300'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "open(os.path.join(os.environ['PID_DIR'], 'pid'), 'w').write(str(p.pid))\n"
            "time.sleep(300)\n"
        )
        pid_dir = os.environ['PYTEST_PID_DIR']
        with patch.dict(os.environ, {'PID_DIR': pid_dir}):
            result = svc.execute_bundle(_bundle(script), 's2')
        assert (result.success, result.outcome, result.exit_code) == (False, OUTCOME_TIMED_OUT, None)
        pid = int(open(os.path.join(pid_dir, 'pid')).read())
        try:
            assert _wait_until_gone(pid)
        finally:
            if _is_running(pid):
                os.kill(pid, signal.SIGKILL)

    def test_temp_files_go_to_the_job_directory(self):
        script = (
            "import os, tempfile\n"
            "print(os.path.realpath(tempfile.gettempdir()) == os.path.realpath(os.getcwd()))\n"
        )
        result = ExecuteServiceImpl(None).execute_bundle(_bundle(script), 's3')
        assert result.output.strip() == 'True'

    def test_root_enclave_kills_every_process_of_the_script_user(self):
        with patch.object(execute_service_impl.os, 'geteuid', return_value=0), \
                patch.object(execute_service_impl.subprocess, 'run') as run:
            execute_service_impl._kill_script_user_processes()
        args, kwargs = run.call_args
        assert args[0][1:] == ['-c', 'import os, signal; os.kill(-1, signal.SIGKILL)']
        assert kwargs['preexec_fn'] is execute_service_impl._drop_privileges

    def test_unprivileged_process_never_sweeps(self):
        with patch.object(execute_service_impl.os, 'geteuid', return_value=1000), \
                patch.object(execute_service_impl.subprocess, 'run') as run:
            execute_service_impl._kill_script_user_processes()
        run.assert_not_called()

    def test_root_enclave_removes_script_user_files_but_keeps_the_job_directory(self, tmp_path):
        shared = tmp_path / 'shared'
        job_dir = shared / 'job'
        leftover_dir = shared / 'leftover'
        for d in (job_dir, leftover_dir):
            d.mkdir(parents=True)
        (leftover_dir / 'inner').write_text('x')
        (shared / 'leftover.txt').write_text('x')

        with patch.object(execute_service_impl.os, 'geteuid', return_value=0), \
                patch.object(execute_service_impl, 'SCRIPT_UID', os.getuid()), \
                patch.object(execute_service_impl, '_SHARED_TEMP_DIRS', (str(shared), str(tmp_path / 'missing'))):
            execute_service_impl._remove_script_user_files(keep=str(job_dir))

        assert sorted(p.name for p in shared.iterdir()) == ['job']

    def test_files_of_other_users_are_left_alone(self, tmp_path):
        (tmp_path / 'enclave.sock').write_text('x')
        with patch.object(execute_service_impl.os, 'geteuid', return_value=0), \
                patch.object(execute_service_impl, 'SCRIPT_UID', os.getuid() + 1), \
                patch.object(execute_service_impl, '_SHARED_TEMP_DIRS', (str(tmp_path),)):
            execute_service_impl._remove_script_user_files(keep=str(tmp_path / 'job'))
        assert (tmp_path / 'enclave.sock').exists()


@pytest.fixture(autouse=True)
def _pid_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('PYTEST_PID_DIR', str(tmp_path))


class TestOutcome:
    def test_success(self):
        result = ExecuteServiceImpl(None).execute_bundle(_bundle("print('ok')\n"), 's1')
        assert (result.success, result.outcome, result.exit_code) == (True, OUTCOME_SUCCEEDED, 0)

    def test_non_zero_exit(self):
        result = ExecuteServiceImpl(None).execute_bundle(_bundle("import sys\nsys.exit(3)\n"), 's2')
        assert (result.success, result.outcome, result.exit_code) == (False, OUTCOME_FAILED, 3)
        assert result.files == []

    def test_bundle_without_a_script(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('notes.txt', 'x')
        result = ExecuteServiceImpl(None).execute_bundle(buf.getvalue(), 's3')
        assert (result.success, result.outcome, result.exit_code) == (False, OUTCOME_INVALID_BUNDLE, None)


def _handler(exec_result):
    decrypt = MagicMock()
    decrypt.decrypt_combined_hybrid_data.return_value = (True, b'zip')
    execute = MagicMock()
    execute.execute_bundle.return_value = exec_result
    attestation = MagicMock()
    attestation.create_execution_attestation.return_value = (True, {'attestation': {'attestation_document': 'DOC'}})
    return RequestHandlerImpl(decrypt, execute, MagicMock(), attestation), attestation, execute


class TestSignedRecordOfEveryRun:
    def test_failed_run_is_signed_with_its_outcome_and_error_hash(self):
        handler, attestation, _ = _handler(BundleResult(False, 'Traceback: boom', [], OUTCOME_FAILED, 1))
        resp = handler._execute_encrypted_script({
            'session_id': 's', 'encrypted_data': 'x', 'platform_job_id': 'JOB-1', 'attempt_id': 'ab' * 16,
        })

        assert resp['success'] is False
        assert resp['error'] == 'Execution failed: Traceback: boom'
        assert (resp['outcome'], resp['exit_code']) == (OUTCOME_FAILED, 1)
        assert resp['attestation'] == {'attestation': {'attestation_document': 'DOC'}}
        assert 'output' not in resp and 'files' not in resp

        kwargs = attestation.create_execution_attestation.call_args.kwargs
        assert kwargs['outcome'] == OUTCOME_FAILED
        assert kwargs['exit_code'] == 1
        assert kwargs['error_hash'] == hashlib.sha256(resp['error'].encode()).hexdigest()
        assert kwargs['output'] == ''
        assert kwargs['files_manifest_sha256'] == EMPTY_MANIFEST_SHA256
        assert kwargs['script_bytes'] == b'zip'
        assert (kwargs['platform_job_id'], kwargs['attempt_id']) == ('JOB-1', 'ab' * 16)

    def test_failed_run_keeps_its_error_when_signing_fails(self):
        handler, attestation, _ = _handler(BundleResult(False, 'boom', [], OUTCOME_FAILED, 1))
        attestation.create_execution_attestation.return_value = (False, {'error': 'NSM_EXCEPTION'})
        resp = handler._execute_encrypted_script({'session_id': 's', 'encrypted_data': 'x'})
        assert resp['success'] is False
        assert 'attestation' not in resp
        assert resp['enclave_proof']['attestation_available'] is False

    def test_successful_run_is_signed_with_its_outcome_and_identifiers(self):
        handler, attestation, _ = _handler(BundleResult(True, 'out', [], OUTCOME_SUCCEEDED, 0))
        resp = handler._execute_encrypted_script({
            'session_id': 's', 'encrypted_data': 'x', 'platform_job_id': 'JOB-1', 'attempt_id': 'cd' * 16,
        })
        assert (resp['success'], resp['outcome'], resp['exit_code']) == (True, OUTCOME_SUCCEEDED, 0)
        kwargs = attestation.create_execution_attestation.call_args.kwargs
        assert (kwargs['outcome'], kwargs['exit_code']) == (OUTCOME_SUCCEEDED, 0)
        assert (kwargs['platform_job_id'], kwargs['attempt_id']) == ('JOB-1', 'cd' * 16)
        assert kwargs.get('error_hash') is None

    @pytest.mark.parametrize('field', ['platform_job_id', 'attempt_id'])
    @pytest.mark.parametrize('value', ['', 'a' * 65, 'has space', 'quote"', 7])
    def test_malformed_identifier_is_refused_before_anything_runs(self, field, value):
        handler, attestation, execute = _handler(BundleResult(True, 'out', [], OUTCOME_SUCCEEDED, 0))
        resp = handler.handle_request(json.dumps({
            'operation': 'execute_script_rsa_hybrid', 'session_id': 's', 'encrypted_data': 'x', field: value,
        }))
        assert resp['success'] is False
        assert f'Invalid {field}' in resp['error']
        execute.execute_bundle.assert_not_called()
        attestation.create_execution_attestation.assert_not_called()


@pytest.fixture
def svc():
    service = AttestationService()
    captured = {}

    def fake_generate(user_data=None, nonce=None, public_key=None):
        captured['user_data'] = user_data
        return True, {'attestation_document': 'DOC'}

    service.generate_attestation = fake_generate
    service._captured = captured
    return service


class TestSignedFields:
    def test_outcome_and_identifiers_are_in_the_signed_data(self, svc):
        ok, result = svc.create_execution_attestation(
            job_id='rsa-session-1', output='', script_bytes=b'zip', dataset_bytes=b'csv',
            external_nonce=bytes(32), context_hash='c' * 64, files_manifest_sha256=EMPTY_MANIFEST_SHA256,
            outcome=OUTCOME_FAILED, exit_code=1, error_hash='e' * 64,
            platform_job_id='JOB-MVGTRGV2', attempt_id='ab' * 16,
        )
        assert ok is True
        signed = json.loads(svc._captured['user_data'])
        assert signed['job_id'] == 'rsa-session-1'
        assert signed['output_hash'] == EMPTY_SHA256
        expected = {
            'outcome': OUTCOME_FAILED, 'exit_code': 1, 'error_hash': 'e' * 64,
            'platform_job_id': 'JOB-MVGTRGV2', 'attempt_id': 'ab' * 16,
        }
        assert {k: signed[k] for k in expected} == expected
        assert {k: result['proof'][k] for k in expected} == expected
        assert len(svc._captured['user_data']) <= MAX_USER_DATA_BYTES

    def test_largest_record_fits_the_signing_limit(self, svc):
        ok, _ = svc.create_execution_attestation(
            job_id='rsa-session-12345678', output='', script_bytes=b'zip', dataset_bytes=b'csv',
            context_hash='c' * 64, files_manifest_sha256=EMPTY_MANIFEST_SHA256,
            outcome='output_rejected', exit_code=-15, error_hash='e' * 64,
            platform_job_id='j' * 64, attempt_id='a' * 64,
        )
        assert ok is True
        assert len(svc._captured['user_data']) <= MAX_USER_DATA_BYTES

    def test_fields_not_supplied_are_not_signed(self, svc):
        svc.create_execution_attestation(job_id='s', output='out')
        signed = json.loads(svc._captured['user_data'])
        assert not {'outcome', 'exit_code', 'error_hash', 'platform_job_id', 'attempt_id'} & set(signed)

    def test_record_over_the_signing_limit_is_refused(self, svc):
        ok, result = svc.create_execution_attestation(job_id='s' * 2000, output='out')
        assert ok is False
        assert result['error'] == 'USER_DATA_TOO_LARGE'
        assert 'user_data' not in svc._captured
