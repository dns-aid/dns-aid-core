# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for sdk.mesh — MeshConnection, MeshTransport, DirectMesh* ABCs."""

from __future__ import annotations

import pytest

from dns_aid.sdk.mesh import (
    _MESH_TRANSPORTS,
    DirectMeshConnection,
    DirectMeshTransport,
    MeshConnection,
    MeshNotAvailableError,
    MeshTransport,
    get_default_mesh,
    register_default_mesh,
)

# ── Concrete test doubles ───────────────────────────────────────


class StubMeshConnection(MeshConnection):
    """Minimal concrete MeshConnection for testing."""

    def __init__(self) -> None:
        self.opened = False
        self.closed = False
        self._buffer = b""

    async def open(self, *, target: str, port: int = 443, mesh_meta: str | None = None) -> None:
        self.opened = True
        self.target = target
        self.port = port
        self.mesh_meta = mesh_meta

    async def read(self, n: int = -1) -> bytes:
        data = self._buffer[:n] if n > 0 else self._buffer
        self._buffer = self._buffer[len(data) :]
        return data

    async def write(self, data: bytes) -> None:
        self._buffer += data

    async def close(self) -> None:
        self.closed = True


class StubMeshTransport(MeshTransport):
    """Minimal concrete MeshTransport for testing."""

    @property
    def mesh_name(self) -> str:
        return "stub"

    async def connect(
        self, *, target: str, port: int = 443, mesh_meta: str | None = None
    ) -> StubMeshConnection:
        conn = StubMeshConnection()
        await conn.open(target=target, port=port, mesh_meta=mesh_meta)
        return conn


# ── MeshConnection ABC tests ────────────────────────────────────


class TestMeshConnectionABC:
    """Test that MeshConnection ABC enforces the contract."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            MeshConnection()  # type: ignore[abstract]

    async def test_concrete_open_read_write_close(self) -> None:
        conn = StubMeshConnection()
        await conn.open(target="agent.example.com", port=8443, mesh_meta='{"svc":"x"}')
        assert conn.opened
        assert conn.target == "agent.example.com"
        assert conn.port == 8443
        assert conn.mesh_meta == '{"svc":"x"}'

        await conn.write(b"hello")
        data = await conn.read(5)
        assert data == b"hello"

        await conn.close()
        assert conn.closed

    async def test_async_context_manager(self) -> None:
        conn = StubMeshConnection()
        await conn.open(target="x.com")

        async with conn:
            await conn.write(b"test")
            assert await conn.read() == b"test"

        assert conn.closed


# ── MeshTransport ABC tests ─────────────────────────────────────


class TestMeshTransportABC:
    """Test that MeshTransport ABC enforces the contract."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            MeshTransport()  # type: ignore[abstract]

    async def test_concrete_connect(self) -> None:
        transport = StubMeshTransport()
        assert transport.mesh_name == "stub"

        conn = await transport.connect(target="agent.example.com", mesh_meta='{"svc":"billing"}')
        assert isinstance(conn, StubMeshConnection)
        assert conn.opened
        assert conn.target == "agent.example.com"

    async def test_close_is_optional_noop(self) -> None:
        transport = StubMeshTransport()
        await transport.close()  # Should not raise


# ── DirectMeshConnection tests ──────────────────────────────────


class TestDirectMeshConnection:
    """Test DirectMeshConnection (httpx wrapper)."""

    async def test_open_creates_client_when_none(self) -> None:
        conn = DirectMeshConnection()
        await conn.open(target="agent.example.com", port=443)
        assert conn.http_client is not None
        await conn.close()

    async def test_open_reuses_provided_client(self) -> None:
        import httpx

        client = httpx.AsyncClient()
        conn = DirectMeshConnection(http_client=client)
        await conn.open(target="x.com")
        assert conn.http_client is client
        await conn.close()
        # Does NOT close provided client (owns_client=False)
        assert not client.is_closed
        await client.aclose()

    async def test_read_raises_not_implemented(self) -> None:
        conn = DirectMeshConnection()
        await conn.open(target="x.com")
        with pytest.raises(NotImplementedError, match="raw read"):
            await conn.read()
        await conn.close()

    async def test_write_raises_not_implemented(self) -> None:
        conn = DirectMeshConnection()
        await conn.open(target="x.com")
        with pytest.raises(NotImplementedError, match="raw write"):
            await conn.write(b"data")
        await conn.close()

    def test_http_client_raises_before_open(self) -> None:
        conn = DirectMeshConnection()
        with pytest.raises(RuntimeError, match="not opened"):
            _ = conn.http_client


# ── DirectMeshTransport tests ───────────────────────────────────


class TestDirectMeshTransport:
    """Test DirectMeshTransport (default, no overlay)."""

    def test_mesh_name(self) -> None:
        transport = DirectMeshTransport()
        assert transport.mesh_name == "direct"

    async def test_connect_returns_direct_connection(self) -> None:
        transport = DirectMeshTransport()
        conn = await transport.connect(target="agent.example.com")
        assert isinstance(conn, DirectMeshConnection)
        assert conn.http_client is not None
        await conn.close()


# ── MeshNotAvailableError tests ─────────────────────────────────


class TestMeshNotAvailableError:
    """Test error message and attributes."""

    def test_message_includes_mesh_name(self) -> None:
        err = MeshNotAvailableError("ziti")
        assert err.mesh == "ziti"
        assert "ziti" in str(err)
        assert "register_mesh" in str(err)


# ── Module-level registry tests ─────────────────────────────────


class TestModuleRegistry:
    """Test register_default_mesh / get_default_mesh."""

    def test_register_and_get(self) -> None:
        transport = StubMeshTransport()
        old = _MESH_TRANSPORTS.copy()
        try:
            register_default_mesh("stub", transport)
            assert get_default_mesh("stub") is transport
        finally:
            _MESH_TRANSPORTS.clear()
            _MESH_TRANSPORTS.update(old)

    def test_get_unknown_returns_none(self) -> None:
        assert get_default_mesh("nonexistent") is None
