"""Shared pytest fixtures for God's Eye test suite."""

from pathlib import Path

import pytest

from godseye.api.app import AppContainer


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Provide an isolated temporary SQLite database path per test."""
    return str(tmp_path / "test_godseye.db")


@pytest.fixture
def container(temp_db_path: str) -> AppContainer:
    """Provide a fresh AppContainer backed by a temporary database."""
    return AppContainer(db_path=temp_db_path)
