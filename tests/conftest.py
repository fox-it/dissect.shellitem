import os
import pathlib

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


@pytest.fixture
def xp_remote_lnk_file():
    return pathlib.Path(absolute_path("data/remote.file.xp.lnk"))


@pytest.fixture
def xp_remote_lnk_dir():
    return pathlib.Path(absolute_path("data/remote.directory.xp.lnk"))


@pytest.fixture
def win7_local_lnk_dir():
    return pathlib.Path(absolute_path("data/local.directory.seven.lnk"))
