# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Backward-compatibility regression tests for ``SigV4AuthHandler`` (T020).

Locks the existing behavior so any future change to the explicit-credentials
extension cannot accidentally regress callers who rely on the boto3 default
credential chain. These tests pass against the current SDK and must continue
to pass after T021 lands the explicit-credentials extension.

The invariants:

1. Every existing constructor call pattern continues to work without source
   change (FR-009).
2. When no explicit credentials are supplied, the handler still routes to
   the boto3 default credential chain (env vars → ``~/.aws/credentials`` →
   IAM role / instance profile).
3. The constructor's signature does not lose any existing parameter.
"""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

from dns_aid.sdk.auth.sigv4 import SigV4AuthHandler


class TestSigV4ConstructorBackwardCompat:
    """All existing constructor call patterns continue to function."""

    def test_construct_with_region_only(self) -> None:
        """Bare-minimum existing pattern: just region."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_create_signer:
            mock_create_signer.return_value = (MagicMock(), MagicMock())
            handler = SigV4AuthHandler(region="us-east-1")
            assert handler.auth_type == "sigv4"
            mock_create_signer.assert_called_once_with("us-east-1", "vpc-lattice-svcs", None)

    def test_construct_with_explicit_service(self) -> None:
        """Existing pattern with API Gateway service override."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_create_signer:
            mock_create_signer.return_value = (MagicMock(), MagicMock())
            SigV4AuthHandler(region="us-east-1", service="execute-api")
            mock_create_signer.assert_called_once_with("us-east-1", "execute-api", None)

    def test_construct_with_profile_name(self) -> None:
        """Existing pattern with named AWS profile."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_create_signer:
            mock_create_signer.return_value = (MagicMock(), MagicMock())
            SigV4AuthHandler(region="us-east-1", profile_name="prod")
            mock_create_signer.assert_called_once_with("us-east-1", "vpc-lattice-svcs", "prod")


class TestSigV4SignatureBackwardCompat:
    """The constructor signature retains all existing parameters."""

    def test_constructor_has_region_parameter(self) -> None:
        sig = inspect.signature(SigV4AuthHandler.__init__)
        assert "region" in sig.parameters

    def test_constructor_has_service_parameter_with_default(self) -> None:
        sig = inspect.signature(SigV4AuthHandler.__init__)
        assert "service" in sig.parameters
        assert sig.parameters["service"].default == "vpc-lattice-svcs"

    def test_constructor_has_profile_name_parameter_with_default(self) -> None:
        sig = inspect.signature(SigV4AuthHandler.__init__)
        assert "profile_name" in sig.parameters
        assert sig.parameters["profile_name"].default is None
