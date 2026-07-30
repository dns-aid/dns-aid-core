# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for DNS-AID's untrusted-input parsers.

Fuzzes the pure parsing functions that consume untrusted data (DNS record
text, TXT values, FQDNs, HTTP index documents, user-supplied names). Expected
rejections (`ValueError`, which covers `ValidationError` and pydantic
validation errors) are caught; any other exception, hang, or memory blowup is
a finding.

Run locally (Linux, Python <= 3.11 for atheris wheels):

    pip install atheris
    python tests/fuzz/fuzz_parsers.py -max_total_time=60

CI runs this weekly via .github/workflows/fuzz.yml. The file deliberately has
no ``test_`` prefix so pytest does not collect it.
"""

import contextlib
import json
import sys

import atheris

with atheris.instrument_imports():
    from dns_aid.core.dcv import _parse_txt_value
    from dns_aid.core.discoverer import _parse_fqdn, _parse_svcb_custom_params
    from dns_aid.core.fqdn import parse_dnsaid_fqdn
    from dns_aid.core.http_index import parse_http_index
    from dns_aid.core.indexer import parse_index_txt
    from dns_aid.utils import validation

_VALIDATORS = (
    validation.validate_agent_name,
    validation.validate_domain,
    validation.validate_endpoint,
    validation.validate_fqdn,
    validation.validate_version,
    validation.validate_well_known_path,
    validation.validate_svcparam_value,
)


def _fuzz_validators(s: str) -> None:
    for fn in _VALIDATORS:
        # rejection is the expected outcome for hostile input
        with contextlib.suppress(ValueError):
            fn(s)


def _fuzz_http_index(s: str) -> None:
    try:
        data = json.loads(s)
    except (ValueError, RecursionError):
        return
    if isinstance(data, dict):
        with contextlib.suppress(ValueError):
            parse_http_index(data)


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 6)
    s = fdp.ConsumeUnicodeNoSurrogates(4096)

    if choice == 0:
        _parse_svcb_custom_params(s)
    elif choice == 1:
        parse_dnsaid_fqdn(s)
    elif choice == 2:
        _parse_fqdn(s)
    elif choice == 3:
        with contextlib.suppress(ValueError):
            parse_index_txt(s)
    elif choice == 4:
        with contextlib.suppress(ValueError):
            _parse_txt_value(s)
    elif choice == 5:
        _fuzz_http_index(s)
    else:
        _fuzz_validators(s)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
