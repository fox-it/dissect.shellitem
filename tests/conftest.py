from pathlib import Path

import pytest


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename)


@pytest.fixture
def xp_modified_remote_lnk_file() -> Path:
    return absolute_path("data/modified_remote.file.xp.lnk")


@pytest.fixture
def xp_remote_lnk_file() -> Path:
    return absolute_path("data/remote.file.xp.lnk")


@pytest.fixture
def xp_remote_lnk_dir() -> Path:
    return absolute_path("data/remote.directory.xp.lnk")


@pytest.fixture
def win7_local_lnk_dir() -> Path:
    return absolute_path("data/local.directory.seven.lnk")


@pytest.fixture
def win81_downloads_lnk_dir() -> Path:
    return absolute_path("data/downloads.win81.lnk")


@pytest.fixture
def vista_idlist_lnk_file() -> Path:
    return absolute_path("data/vista.idlist.lnk")
