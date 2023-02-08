import os
from pathlib import Path

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


@pytest.fixture
def xp_remote_lnk_file():
    return Path(absolute_path("data/remote.file.xp.lnk"))


@pytest.fixture
def xp_remote_lnk_dir():
    return Path(absolute_path("data/remote.directory.xp.lnk"))


@pytest.fixture
def win7_local_lnk_dir():
    return Path(absolute_path("data/local.directory.seven.lnk"))


@pytest.fixture
def win81_downloads_lnk_dir():
    return Path(absolute_path("data/downloads.win81.lnk"))
