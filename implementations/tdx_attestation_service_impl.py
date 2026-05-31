"""
Intel TDX attestation service (Epsilon TDX backend).

Mirrors AttestationService (Nitro) method-for-method, but produces a hardware
-signed Intel TDX *quote* instead of a Nitro NSM COSE_Sign1 document.

Design (deliberate TDX-vs-Nitro differences, documented for the paper):
  * Nitro binds three separate slots -- a <=1024-byte user_data JSON, a 32-byte
    nonce, and a public_key -- into the NSM document. TDX exposes a single hard
    64-byte REPORTDATA field. We therefore fold every per-execution field into
    one canonical JSON and commit to it with SHA-512 (exactly 64 bytes, no
    waste): REPORTDATA = SHA-512(canonical proof JSON). The full pre-image
    travels back to the coordinator out-of-band in `proof.proof_canonical`, and
    the verifier recomputes SHA-512(proof_canonical) == REPORTDATA.
  * The quote is produced by shelling out to the `tdquote` Go helper
    (go-tdx-guest), the exact path validated on the GCP C3 TDX VM. configfs-tsm
    or /dev/tdx_guest is selected by the helper; both require root.
"""
import base64
import hashlib
import json
import logging
import os
import subprocess
import time
from typing import Tuple, Dict, Any, Optional

from interfaces.attestation_interface import IAttestationService

logger = logging.getLogger(__name__)


DEFAULT_TDQUOTE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tdx", "tdquote", "tdquote",
)
TDQUOTE_TIMEOUT_SECONDS = int(os.getenv("TDQUOTE_TIMEOUT_SECONDS", "60"))


class TdxAttestationService(IAttestationService):
    """Produces Intel TDX quotes binding per-execution proof into REPORTDATA."""

    def __init__(self, tdquote_bin: Optional[str] = None):
        self._tdquote_bin = tdquote_bin or os.getenv("TDQUOTE_BIN", DEFAULT_TDQUOTE_BIN)

    # ---- low-level quote generation -------------------------------------

    def _get_td_quote(self, report_data: bytes) -> bytes:
        """Mint a TD quote binding exactly `report_data` (must be 64 bytes)."""
        if len(report_data) != 64:
            raise ValueError(f"REPORTDATA must be 64 bytes, got {len(report_data)}")
        proc = subprocess.run(
            [self._tdquote_bin],
            input=report_data.hex().encode(),
            capture_output=True,
            timeout=TDQUOTE_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"tdquote helper failed: {proc.stderr.decode(errors='replace')}")
        if not proc.stdout:
            raise RuntimeError("tdquote helper returned empty quote")
        return proc.stdout

    @staticmethod
    def _report_data_from(*chunks: Optional[bytes]) -> bytes:
        """Collapse arbitrary slots into one 64-byte commitment (SHA-512)."""
        h = hashlib.sha512()
        for c in chunks:
            if c is None:
                continue
            h.update(len(c).to_bytes(4, "big"))  # length-prefix to avoid ambiguity
            h.update(c)
        return h.digest()

    # ---- IAttestationService -------------------------------------------

    def generate_attestation(
        self,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Generic attestation: commit (user_data, nonce, public_key) -> quote."""
        try:
            report_data = self._report_data_from(user_data, nonce, public_key)
            quote = self._get_td_quote(report_data)
            return True, {
                "backend": "tdx",
                "format": "tdx_quote",
                "attestation_document": base64.b64encode(quote).decode(),
                "attestation_document_length": len(quote),
                "report_data": report_data.hex(),
            }
        except Exception as e:  # noqa: BLE001 - report as structured error like Nitro
            logger.error(f"[TDX-ATTESTATION] Failed: {e}")
            return False, {"error": "TDX_QUOTE_ERROR", "message": str(e), "is_real_tdx": self.is_real_enclave}

    def create_execution_attestation(
        self,
        job_id: str,
        output: str,
        script_bytes: Optional[bytes] = None,
        dataset_bytes: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        atl_nonce: Optional[bytes] = None,
        atl_context_hash: Optional[bytes] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Per-execution attestation. Same proof fields as the Nitro backend,
        plus the ATL commitment fields, all committed via one 64-byte REPORTDATA."""
        try:
            script_hash = hashlib.sha256(script_bytes).hexdigest() if script_bytes else ""
            dataset_hash = hashlib.sha256(dataset_bytes).hexdigest() if dataset_bytes else ""
            if nonce is None:
                nonce = os.urandom(32)

            proof_data = {
                "job_id": job_id,
                "script_hash": script_hash,
                "dataset_hash": dataset_hash,
                "output_hash": hashlib.sha256(output.encode()).hexdigest(),
                "timestamp": int(time.time()),
                "nonce": nonce.hex(),
                "atl_nonce": atl_nonce.hex() if atl_nonce is not None else None,
                "atl_context_hash": atl_context_hash.hex() if atl_context_hash is not None else None,
                "backend": "tdx",
            }
            # Canonical, separator-stable bytes the verifier must reproduce exactly.
            proof_canonical = json.dumps(proof_data, sort_keys=True, separators=(",", ":"))
            report_data = hashlib.sha512(proof_canonical.encode()).digest()  # 64 bytes

            quote = self._get_td_quote(report_data)

            return True, {
                "attestation": {
                    "backend": "tdx",
                    "format": "tdx_quote",
                    "attestation_document": base64.b64encode(quote).decode(),
                    "attestation_document_length": len(quote),
                    "report_data": report_data.hex(),
                },
                "proof": {
                    **proof_data,
                    # Exact bytes the coordinator re-hashes: SHA-512(proof_canonical) == report_data
                    "proof_canonical": proof_canonical,
                },
                "verification_guide": {
                    "step_1": "Base64-decode attestation_document into the raw TD quote",
                    "step_2": "Verify the quote signature and PCK certificate chain against the Intel SGX/TDX roots (go-tdx-guest verify)",
                    "step_3": "Compare MRTD/RTMR[0..3] against the published enclave-image measurements",
                    "step_4": "Extract REPORTDATA (64 bytes) from the verified quote",
                    "step_5": "Recompute SHA-512(proof.proof_canonical) and confirm it equals REPORTDATA",
                    "step_6": "Recompute SHA-256(output) and confirm it equals proof.output_hash",
                    "conclusion": "If all steps pass, this output was produced inside the verified TDX trust domain bound to this exact job/script/dataset",
                },
            }
        except Exception as e:  # noqa: BLE001
            logger.error(f"[TDX-ATTESTATION] create_execution_attestation failed: {e}")
            return False, {"error": "TDX_ATTESTATION_ERROR", "message": str(e), "is_real_tdx": self.is_real_enclave}

    @property
    def is_real_enclave(self) -> bool:
        """True when a TDX quote interface is present (configfs-tsm or device)."""
        return os.path.exists("/sys/kernel/config/tsm/report") or os.path.exists("/dev/tdx_guest")
