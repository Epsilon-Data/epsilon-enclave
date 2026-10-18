"""Tests for output files (phase 2): collection rules, manifest, attestation binding."""
import base64
import hashlib
import io
import json
import os
import zipfile
from unittest.mock import MagicMock

import pytest

from implementations.attestation_service_impl import AttestationService
from implementations.execute_service_impl import ExecuteServiceImpl
from implementations.output_files import (
    OutputFilesError,
    build_files_manifest,
    canonical_manifest_bytes,
    collect_output_files,
    files_manifest_sha256,
)
from implementations.request_handler_impl import RequestHandlerImpl
from implementations.tdx_attestation_service_impl import TdxAttestationService

MAX_FILES = 20
MAX_BYTES = 10 * 1024 * 1024

# Known-answer vector shared with the coordinator, job-scheduler and verifier.
KAT_FILES = [
    ('plot.png', b'\x89PNG\r\n\x1a\n'),
    ('a.csv', b'x,y\n1,2\n'),
]
KAT_CANONICAL = (
    b'[{"name":"a.csv","sha256":"81bf9fa83c6f7f151bd491a98cd7d933de3965289e3ebd77c6c425f7eaa16392",'
    b'"size":8,"type":"text/csv"},'
    b'{"name":"plot.png","sha256":"4c4b6a3be1314ab86138bef4314dde022e600960d8689a2c8f8631802d20dab6",'
    b'"size":8,"type":"image/png"}]'
)
KAT_SHA256 = 'a37a007f52723efc320ec5dfa00d80ee054d7733627a303b33b315c820958f9c'
EMPTY_SHA256 = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'


def _write(path, data=b'data'):
    with open(path, 'wb') as f:
        f.write(data)


@pytest.fixture
def out_dir(tmp_path):
    d = tmp_path / 'outputs'
    d.mkdir()
    return d


class TestCollect:
    def test_mixed_allowed_files(self, out_dir):
        contents = {
            'b.CSV': b'x\n1\n', 'chart.png': b'png', 'photo.JPG': b'jpg', 'p.jpeg': b'jpeg',
            'r.json': b'{}', 'notes.txt': b'hi', 'report.pdf': b'%PDF', 'a_b-c.1.csv': b'',
        }
        for name, data in contents.items():
            _write(out_dir / name, data)

        files = collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)

        assert [f['name'] for f in files] == sorted(contents)
        by_name = {f['name']: f for f in files}
        assert by_name['b.CSV']['type'] == 'text/csv'
        assert by_name['chart.png']['type'] == 'image/png'
        assert by_name['photo.JPG']['type'] == 'image/jpeg'
        assert by_name['p.jpeg']['type'] == 'image/jpeg'
        assert by_name['r.json']['type'] == 'application/json'
        assert by_name['notes.txt']['type'] == 'text/plain'
        assert by_name['report.pdf']['type'] == 'application/pdf'
        for name, data in contents.items():
            assert by_name[name]['content'] == data
            assert by_name[name]['size'] == len(data)
            assert by_name[name]['sha256'] == hashlib.sha256(data).hexdigest()

    def test_missing_dir_is_no_files(self, tmp_path):
        assert collect_output_files(str(tmp_path / 'nope'), MAX_FILES, MAX_BYTES) == []

    def test_empty_dir_is_no_files(self, out_dir):
        assert collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES) == []

    def test_subdirectory_rejected(self, out_dir):
        (out_dir / 'sub').mkdir()
        with pytest.raises(OutputFilesError, match='subdirectory'):
            collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)

    def test_symlink_rejected(self, out_dir, tmp_path):
        target = tmp_path / 'secret.csv'
        _write(target)
        os.symlink(target, out_dir / 'link.csv')
        with pytest.raises(OutputFilesError, match='symlink'):
            collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)

    def test_outputs_dir_symlink_rejected(self, tmp_path):
        real = tmp_path / 'real'
        real.mkdir()
        os.symlink(real, tmp_path / 'outputs')
        with pytest.raises(OutputFilesError):
            collect_output_files(str(tmp_path / 'outputs'), MAX_FILES, MAX_BYTES)

    @pytest.mark.parametrize('name', ['.hidden.csv', '-a.csv', 'a b.csv', 'a$.csv', 'x' * 101 + '.csv'])
    def test_bad_name_rejected(self, out_dir, name):
        _write(out_dir / name)
        with pytest.raises(OutputFilesError, match='invalid file name'):
            collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)

    @pytest.mark.parametrize('name', ['a.py', 'a.svg', 'a.html', 'noext', 'a.csv.exe', 'a.'])
    def test_bad_extension_rejected(self, out_dir, name):
        _write(out_dir / name)
        with pytest.raises(OutputFilesError, match='file type not allowed'):
            collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)

    def test_too_many_files_rejected(self, out_dir):
        for i in range(4):
            _write(out_dir / f'f{i}.txt')
        assert len(collect_output_files(str(out_dir), 4, MAX_BYTES)) == 4
        _write(out_dir / 'f4.txt')
        with pytest.raises(OutputFilesError, match='too many files'):
            collect_output_files(str(out_dir), 4, MAX_BYTES)

    def test_too_large_rejected(self, out_dir):
        _write(out_dir / 'a.txt', b'x' * 60)
        _write(out_dir / 'b.txt', b'x' * 40)
        assert len(collect_output_files(str(out_dir), MAX_FILES, 100)) == 2
        with pytest.raises(OutputFilesError, match='total size too large'):
            collect_output_files(str(out_dir), MAX_FILES, 99)


class TestManifest:
    def _files(self):
        return [
            {'name': n, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest(), 'type': t, 'content': d}
            for (n, d), t in zip(KAT_FILES, ['image/png', 'text/csv'])
        ]

    def test_manifest_sorted_and_stripped_of_content(self):
        manifest = build_files_manifest(self._files())
        assert [m['name'] for m in manifest] == ['a.csv', 'plot.png']
        assert all(set(m) == {'name', 'size', 'sha256', 'type'} for m in manifest)

    def test_canonical_bytes_known_answer(self):
        assert canonical_manifest_bytes(build_files_manifest(self._files())) == KAT_CANONICAL

    def test_hash_known_answer(self):
        assert files_manifest_sha256(build_files_manifest(self._files())) == KAT_SHA256
        assert hashlib.sha256(KAT_CANONICAL).hexdigest() == KAT_SHA256

    def test_known_answer_from_disk(self, out_dir):
        for name, data in KAT_FILES:
            _write(out_dir / name, data)
        files = collect_output_files(str(out_dir), MAX_FILES, MAX_BYTES)
        assert files_manifest_sha256(build_files_manifest(files)) == KAT_SHA256

    def test_empty_manifest(self):
        assert canonical_manifest_bytes([]) == b'[]'
        assert files_manifest_sha256([]) == EMPTY_SHA256


def _bundle(script):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('main.py', script)
    return buf.getvalue()


class TestExecuteBundle:
    def test_collects_files_and_sets_env(self):
        script = (
            "import os\n"
            "d = os.environ['EPSILON_OUTPUT_DIR']\n"
            "assert os.path.isabs(d) and os.path.isdir(d)\n"
            "assert os.environ['MPLBACKEND'] == 'Agg'\n"
            "assert os.environ['MPLCONFIGDIR'].endswith('.mplconfig')\n"
            "with open(os.path.join(d, 'result.csv'), 'w') as f:\n"
            "    f.write('a,b\\n1,2\\n')\n"
            "print('done')\n"
        )
        ok, output, files = ExecuteServiceImpl(None).execute_bundle(_bundle(script), 's1')
        assert ok, output
        assert 'done' in output
        assert [(f['name'], f['type'], f['content']) for f in files] == [('result.csv', 'text/csv', b'a,b\n1,2\n')]

    def test_no_files_written(self):
        ok, output, files = ExecuteServiceImpl(None).execute_bundle(_bundle("print('x')\n"), 's2')
        assert ok, output
        assert files == []

    def test_rejected_files_fail_execution(self):
        script = (
            "import os\n"
            "with open(os.path.join(os.environ['EPSILON_OUTPUT_DIR'], 'evil.sh'), 'w') as f:\n"
            "    f.write('x')\n"
        )
        ok, output, files = ExecuteServiceImpl(None).execute_bundle(_bundle(script), 's3')
        assert ok is False
        assert output.startswith('Output files rejected: ')
        assert files == []

    def test_failed_script_returns_no_files(self):
        script = (
            "import os\n"
            "with open(os.path.join(os.environ['EPSILON_OUTPUT_DIR'], 'a.csv'), 'w') as f:\n"
            "    f.write('x')\n"
            "raise SystemExit(1)\n"
        )
        ok, _, files = ExecuteServiceImpl(None).execute_bundle(_bundle(script), 's4')
        assert ok is False
        assert files == []

    def test_matplotlib_import_allowed(self):
        ok, _ = ExecuteServiceImpl(None).validate_script('import matplotlib.pyplot as plt\n')
        assert ok


class TestAttestationBinding:
    def test_nitro_proof_includes_files_manifest_sha256(self):
        svc = AttestationService()
        captured = {}

        def fake_generate(user_data=None, nonce=None, public_key=None):
            captured['user_data'] = user_data
            return True, {'attestation_document': 'FAKE'}

        svc.generate_attestation = fake_generate
        ok, result = svc.create_execution_attestation(
            job_id='j', output='out', files_manifest_sha256=KAT_SHA256,
        )
        assert ok
        proof = json.loads(captured['user_data'].decode())
        assert proof['files_manifest_sha256'] == KAT_SHA256
        assert proof['output_hash'] == hashlib.sha256(b'out').hexdigest()
        assert result['proof']['files_manifest_sha256'] == KAT_SHA256

    def test_tdx_proof_includes_files_manifest_sha256(self):
        svc = TdxAttestationService(tdquote_bin='/nonexistent')
        svc._get_td_quote = lambda report_data: b'QUOTE'
        ok, result = svc.create_execution_attestation(
            job_id='j', output='out', files_manifest_sha256=KAT_SHA256,
        )
        assert ok, result
        canonical = json.loads(result['proof']['proof_canonical'])
        assert canonical['files_manifest_sha256'] == KAT_SHA256


class TestRequestHandler:
    def _handler(self, exec_result):
        decrypt = MagicMock()
        decrypt.decrypt_combined_hybrid_data.return_value = (True, b'zip')
        execute = MagicMock()
        execute.execute_bundle.return_value = exec_result
        attestation = MagicMock()
        attestation.create_execution_attestation.return_value = (True, {'attestation': {}})
        handler = RequestHandlerImpl(decrypt, execute, MagicMock(), attestation)
        return handler, attestation

    def test_success_response_has_files_and_manifest_hash(self):
        files = [
            {'name': n, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest(), 'type': t, 'content': d}
            for (n, d), t in sorted(zip(KAT_FILES, ['image/png', 'text/csv']))
        ]
        handler, attestation = self._handler((True, 'out', files))
        resp = handler._execute_encrypted_script({'session_id': 's', 'encrypted_data': 'x'})

        assert resp['success'] is True
        assert resp['files_manifest_sha256'] == KAT_SHA256
        assert [f['name'] for f in resp['files']] == ['a.csv', 'plot.png']
        assert base64.b64decode(resp['files'][1]['content_b64']) == b'\x89PNG\r\n\x1a\n'
        assert set(resp['files'][0]) == {'name', 'size', 'sha256', 'type', 'content_b64'}
        kwargs = attestation.create_execution_attestation.call_args.kwargs
        assert kwargs['files_manifest_sha256'] == KAT_SHA256
        assert kwargs['output'] == 'out'

    def test_no_files_attests_empty_manifest(self):
        handler, attestation = self._handler((True, 'out', []))
        resp = handler._execute_encrypted_script({'session_id': 's', 'encrypted_data': 'x'})
        assert resp['files'] == []
        assert resp['files_manifest_sha256'] == EMPTY_SHA256
        assert attestation.create_execution_attestation.call_args.kwargs['files_manifest_sha256'] == EMPTY_SHA256

    def test_failure_returns_no_files(self):
        handler, attestation = self._handler((False, 'Output files rejected: too many files (21 > 20)', []))
        resp = handler._execute_encrypted_script({'session_id': 's', 'encrypted_data': 'x'})
        assert resp['success'] is False
        assert 'files' not in resp
        assert 'Output files rejected: ' in resp['error']
        attestation.create_execution_attestation.assert_not_called()
