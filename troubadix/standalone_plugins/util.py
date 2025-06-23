# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from troubadix.standalone_plugins.changed_creation_date import git


@contextmanager
def temporary_git_directory() -> Generator[Path, None, None]:

    cwd = Path.cwd()

    with tempfile.TemporaryDirectory() as tempdir:

        try:
            os.chdir(tempdir)
            git("init", "-b", "main")
            git("config", "--local", "user.email", "max.mustermann@example.com")
            git("config", "--local", "user.name", "Max Mustermann")
            yield Path(tempdir)

        finally:
            os.chdir(cwd)
