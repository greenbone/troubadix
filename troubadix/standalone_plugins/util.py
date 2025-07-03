# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from contextlib import contextmanager
from os import chdir
from pathlib import Path
from tempfile import TemporaryDirectory

from troubadix.standalone_plugins.changed_creation_date import git


@contextmanager
def temporary_git_directory():

    cwd = Path.cwd()

    with TemporaryDirectory() as tempdir:

        try:
            chdir(tempdir)
            git("init", "-b", "main")
            git("config", "--local", "user.email", "max.mustermann@example.com")
            git("config", "--local", "user.name", "Max Mustermann")
            yield Path(tempdir)

        finally:
            chdir(cwd)
