"""P1 conformance: every published canonical and boundary fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest_sdk import canonical
from attest_sdk.errors import AttestError

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "attest-spec" / "v1" / "vectors"


def _cases() -> list[dict[str, Any]]:
    manifest = json.loads((VECTORS / "manifest.json").read_bytes())
    kinds = {"canonical", "boundary"}
    return [fx for fx in manifest["fixtures"] if fx["kind"] in kinds]


@pytest.mark.parametrize("fx", _cases(), ids=lambda fx: str(fx["id"]))
def test_published_vector(fx: dict[str, Any]) -> None:
    raw = (VECTORS / str(fx["input"])).read_bytes()
    if "input_bytes" in fx:
        assert len(raw) == fx["input_bytes"]
    source_format = "yaml" if str(fx["input"]).endswith(".yaml") else "json"
    expected = fx["expected"]
    if expected["outcome"] == "valid":
        out = canonical.canonicalize_bytes(raw, source_format=source_format)
        assert out == (VECTORS / str(expected["canonical_file"])).read_bytes()
        assert hashlib.sha256(out).hexdigest() == expected["canonical_sha256"]
        assert len(out) == expected["canonical_bytes"]
    else:
        with pytest.raises(AttestError) as err:
            canonical.canonicalize_bytes(raw, source_format=source_format)
        assert err.value.reason_class == expected["reason_class"]
