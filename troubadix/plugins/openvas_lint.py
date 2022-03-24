#  Copyright (c) 2022 Greenbone Networks GmbH
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
from pathlib import Path
from typing import Iterator

from troubadix.helper import subprocess_cmd, get_root
from troubadix.helper.helper import which
from troubadix.plugin import (
    LinterError,
    FileContentPlugin,
    LinterResult,
    LinterWarning,
)


class CheckOpenvasLint(FileContentPlugin):
    name = "check_openvas_lint"

    @staticmethod
    def run(
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """'openvas-nasl-lint' is required for this step to be executable!
        This script opens a shell in a subprocess and executes
        'openvas-nasl-lint' to check the VT/Include for errors.
        If any kind of error is being found during the subprocess, an error
        will be thrown showing its source.

        Args:
            nasl_file: The VT that is going to be checked
            file_content: The content of the file
            tag_pattern: The pattern to match the tags
            special_tag_pattern: The pattern to match the special tags

        """
        root = get_root(nasl_file)

        if os.environ.get("NASLINTER_DOCKER_RUN", "false") == "true":
            # jf: If the root is different from default openvas plugins path,
            #     we need to make sure that we use the same path structure for
            #     the docker container to run the linting.
            # Default: -v "$(pwd)/scripts:/var/lib/openvas/plugins"
            cmd = (
                "docker run --rm -i --log-driver=none -a stdin -a stdout "
                '-a stderr -v "{root}:{root}" '
                "greenbone/ospd-openvas:stable openvas-nasl-lint "
                "-i {root} {nasl_file}"
            )
        else:
            cmd = "openvas-nasl-lint -i {root} {nasl_file}"
            program = which("openvas-nasl-lint")
            if program is None:
                yield LinterError(
                    "openvas-nasl-lint not found within your PATH. "
                    "Please install 'openvas' and make sure it is available "
                    "within your PATH. "
                )
                return

        exec_cmd = cmd.format(root=str(root), nasl_file=str(nasl_file))

        lint_out, lint_err = subprocess_cmd(exec_cmd)
        report = ""
        if lint_err:
            report += lint_err
        if lint_out:
            report += lint_out

        if " errors found" not in report:
            yield LinterWarning(str(report))
        # nb: "Cannot compile regex" was added here because
        # openvas-nasl-lint currently doesn't treat these as errors.
        # See SC-175.
        elif "0 errors found" not in report or "Cannot compile regex" in report:
            yield LinterError(str(report))
