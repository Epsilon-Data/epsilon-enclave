"""Tests for ATL binding in create_execution_attestation (sprint E4).

Verifies the scaffold (commit dc69270) and request-handler wiring
(commit cbdc3a0) actually bind the coordinator-supplied freshness nonce and
context_hash into the hardware-signed user_data, per TDSC paper §3.5.
"""
import json

import pytest

from implementations.attestation_service_impl import AttestationService


@pytest.fixture
def svc():
    """AttestationService with generate_attestation mocked.

    We test create_execution_attestation's contract — that it builds the
    right proof_data and feeds the right user_data + nonce into the
    underlying NSM call. We don't test the NSM call itself.
    """
    s = AttestationService()
    captured = {}

    def fake_generate(user_data=None, nonce=None, public_key=None):
        captured["user_data"] = user_data
        captured["nonce"] = nonce
        return True, {"attestation_document": "FAKE_BASE64_DOC"}

    s.generate_attestation = fake_generate
    s._captured = captured
    return s


JOB_ID = "deadbeef" * 8
OUTPUT = "hello world"
SCRIPT = b"def run(): pass"
DATASET = b"col1,col2\n1,2\n"


class TestExternalNonceBinding:
    def test_external_nonce_appears_in_proof_data(self, svc):
        external_nonce = bytes.fromhex("aa" * 32)
        ok, result = svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
            external_nonce=external_nonce,
        )
        assert ok is True
        proof_bytes = svc._captured["user_data"]
        proof = json.loads(proof_bytes.decode())
        # external_nonce is the value the coordinator sent; proof_data.nonce
        # is the base64 of that exact nonce.
        import base64
        assert base64.b64decode(proof["nonce"]) == external_nonce
        assert proof.get("nonce_source") != "random"

    def test_nsm_call_receives_external_nonce_as_attestation_nonce(self, svc):
        """The nonce passed to NSM (which signs over it) must equal the
        coordinator-supplied freshness nonce, not a random one."""
        external_nonce = bytes.fromhex("bb" * 32)
        svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
            external_nonce=external_nonce,
        )
        assert svc._captured["nonce"] == external_nonce

    def test_falls_back_to_random_and_marks_non_compliant_when_external_nonce_absent(self, svc):
        ok, result = svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
            external_nonce=None,
        )
        assert ok is True
        proof = json.loads(svc._captured["user_data"].decode())
        assert proof.get("nonce_source") == "random"


class TestContextHashBinding:
    def test_context_hash_appears_in_proof_data(self, svc):
        ctx_hex = "cc" * 32
        ok, _ = svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
            context_hash=ctx_hex,
        )
        assert ok is True
        proof = json.loads(svc._captured["user_data"].decode())
        assert proof.get("context_hash") == ctx_hex

    def test_context_hash_absent_when_not_supplied(self, svc):
        ok, _ = svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
        )
        assert ok is True
        proof = json.loads(svc._captured["user_data"].decode())
        # context_hash either absent or empty string (backwards-compatible)
        assert proof.get("context_hash", "") == ""


class TestSevenFieldUserData:
    """Paper §4.2: user_data binds (job_id, script_hash, dataset_hash,
    output_hash, timestamp, nonce, context_hash). When all are supplied the
    proof_data dict must contain all 7."""

    def test_all_seven_fields_present_when_inputs_supplied(self, svc):
        external_nonce = bytes.fromhex("dd" * 32)
        ctx_hex = "ee" * 32
        ok, _ = svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
            external_nonce=external_nonce,
            context_hash=ctx_hex,
        )
        assert ok is True
        proof = json.loads(svc._captured["user_data"].decode())
        for field in (
            "job_id", "script_hash", "dataset_hash", "output_hash",
            "timestamp", "nonce", "context_hash",
        ):
            assert field in proof, f"missing user_data field: {field}"
            assert proof[field], f"empty user_data field: {field}"

    def test_script_hash_is_sha256_of_script_bytes(self, svc):
        import hashlib
        svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
        )
        proof = json.loads(svc._captured["user_data"].decode())
        assert proof["script_hash"] == hashlib.sha256(SCRIPT).hexdigest()

    def test_dataset_hash_is_sha256_of_dataset_bytes(self, svc):
        import hashlib
        svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
        )
        proof = json.loads(svc._captured["user_data"].decode())
        assert proof["dataset_hash"] == hashlib.sha256(DATASET).hexdigest()

    def test_output_hash_is_sha256_of_output(self, svc):
        import hashlib
        svc.create_execution_attestation(
            job_id=JOB_ID, output=OUTPUT,
            script_bytes=SCRIPT, dataset_bytes=DATASET,
        )
        proof = json.loads(svc._captured["user_data"].decode())
        assert proof["output_hash"] == hashlib.sha256(OUTPUT.encode()).hexdigest()
