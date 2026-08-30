"""G3 signer-local admission: verify raw grant then durably consume it."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from .admission_grant_replay_journal import AdmissionGrantReplayJournal, AdmissionGrantReplayJournalError
from .signer_admission_grant import (
    AdmissionGrantContext, AdmissionGrantError, AdmissionIssuerKeyV1,
    StrictSignerAuthorizationRequestV1, decode_strict_json, verify_admission_grant,
)


class SignerAdmissionRuntimeError(ValueError):
    """Safe G3 admission failure; no internal trust detail is exposed."""


@dataclass(frozen=True)
class SignerAdmissionRuntime:
    """Trusted local binding; no caller provides verified admission objects."""
    context: AdmissionGrantContext
    issuer_keys: Sequence[AdmissionIssuerKeyV1]
    replay_journal: AdmissionGrantReplayJournal
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        if not isinstance(self.context, AdmissionGrantContext):
            raise SignerAdmissionRuntimeError("admission_context_required")
        if not isinstance(self.replay_journal, AdmissionGrantReplayJournal):
            raise SignerAdmissionRuntimeError("admission_replay_journal_required")
        if self.context.signer_role != self.replay_journal.signer_role:
            raise SignerAdmissionRuntimeError("admission_replay_role_mismatch")
        if not self.issuer_keys or any(not isinstance(key, AdmissionIssuerKeyV1) for key in self.issuer_keys):
            raise SignerAdmissionRuntimeError("admission_issuer_keys_required")
        if any(key.signer_role != self.context.signer_role for key in self.issuer_keys):
            raise SignerAdmissionRuntimeError("admission_issuer_role_mismatch")

    def admit(self, *, request: StrictSignerAuthorizationRequestV1, raw_grant: bytes) -> None:
        """G1 -> G2 only. Return is deliberately not an authority object."""
        try:
            artifact = decode_strict_json(raw_grant)
            if not isinstance(artifact, dict) or set(artifact) != {"unsigned_grant", "signature_envelope"}:
                raise AdmissionGrantError("grant_transport_invalid")
            now = self.clock()
            verified = verify_admission_grant(
                unsigned_grant=artifact["unsigned_grant"], signature_envelope=artifact["signature_envelope"],
                request=request, context=self.context, issuer_keys=self.issuer_keys, trusted_now=now,
            )
            grant = artifact["unsigned_grant"]
            result = self.replay_journal.consume_once(
                grant_id=verified.grant_id,
                admission_request_sha256=verified.admission_request_sha256,
                acceptance_run_id=grant["acceptance_run_id"],
                consumed_at=now,
                valid_until=datetime.strptime(grant["valid_until"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo),
            )
            if result.status != "CONSUMED":
                raise SignerAdmissionRuntimeError("admission_grant_already_consumed")
        except (AdmissionGrantError, AdmissionGrantReplayJournalError, ValueError) as exc:
            raise SignerAdmissionRuntimeError("admission_rejected") from exc


def decode_grant_header(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise SignerAdmissionRuntimeError("grant_transport_invalid")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise SignerAdmissionRuntimeError("grant_transport_invalid") from exc
