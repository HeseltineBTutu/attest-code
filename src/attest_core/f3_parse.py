"""F3 parse entry point: strict bytes parsing plus kind dispatch.

`parse_record_bytes` strict-parses source bytes with the project
parser, rejects unknown record kinds, and dispatches to the
per-kind validators. Pure: no I/O beyond the given bytes.
"""

from __future__ import annotations

from attest_core import f3_fields as ff
from attest_core import f3_records_campaign, f3_records_env, f3_records_summary
from attest_core.f3_errors import F3ParseError, F3SchemaError
from attest_core.f3_records import AttemptRecord, TotalRecord, validate_attempt, validate_total
from attest_sdk import canonical
from attest_sdk.errors import AttestError


def parse_record_bytes(
    data: bytes,
) -> (
    AttemptRecord
    | TotalRecord
    | f3_records_env.EnvRecord
    | f3_records_campaign.CampaignRecord
    | f3_records_summary.SummaryRecord
):
    """Strict-parse one record document and validate its schema.

    Byte failures (encoding, syntax, duplicate keys, floats,
    trailing data, limits) raise F3ParseError; structural
    failures raise F3SchemaError. Never uses stdlib `json`.
    """
    if not isinstance(data, bytes):
        raise F3ParseError(rule="PARSE", section="8.2", location="$", reason="input must be bytes")
    try:
        value = canonical.parse_bytes(data)
    except AttestError as exc:
        raise F3ParseError(
            rule="PARSE",
            section="8.2",
            location="$",
            reason=f"{exc.reason_class}: {exc}",
        ) from exc
    if not isinstance(value, dict):
        raise F3SchemaError(
            rule="V-B6",
            section="7",
            location="$",
            reason="top-level JSON value must be an object",
        )
    kind = value.get("record_kind")
    if kind == "attempt":
        return validate_attempt(value)
    if kind == "invocation_total":
        return validate_total(value)
    if kind == "environment":
        return f3_records_env.validate_environment(value)
    if kind == "campaign":
        return f3_records_campaign.validate_campaign(value)
    if kind == "summary":
        return f3_records_summary.validate_summary(value)
    raise F3SchemaError(
        rule="V-B6",
        section="7",
        location="$.record_kind",
        reason=f"unknown record_kind: {kind!r} (expected one of {sorted(ff.RECORD_KINDS)})",
    )
