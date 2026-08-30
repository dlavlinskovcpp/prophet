"""One-shot admission-grant issuer identity for signer A only."""
from .fixed_role_admission_issuer import _issue_fixed_role_admission_grant


def issue_signer_a_admission_grant(config_value, raw_request, acceptance_run_id):
    return _issue_fixed_role_admission_grant(
        fixed_role="A", config_value=config_value, raw_request=raw_request,
        acceptance_run_id=acceptance_run_id,
    )
