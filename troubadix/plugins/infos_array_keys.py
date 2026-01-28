# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import re
from collections.abc import Iterator
from pathlib import Path

from troubadix.helper.remove_comments import remove_comments
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult, LinterWarning

FN_CALL_EXPRESSION = "get_app_version_and_location"
ALLOWED_KEYS = ("cpe", "port", "version", "location", "proto")

# Matches variable assignments: var = get_app_version_and_location
# Also matches: if (!var = get_app_version_and_location(...))
ASSIGN_RE = re.compile(rf"(?P<var_name>\w+)\s*=\s*{FN_CALL_EXPRESSION}")


class CheckInfosArrayKeys(FileContentPlugin):
    name = "check_infos_array_keys"

    def check_content(self, nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        # exclusion for file that declares the method itself
        if nasl_file.name == "host_details.inc":
            return

        clean_content = remove_comments(file_content)

        if FN_CALL_EXPRESSION not in clean_content:
            return

        found_vars = set()
        for match in ASSIGN_RE.finditer(clean_content):
            var_name = match.group("var_name")
            found_vars.add(var_name)
            if var_name != "infos":
                yield LinterWarning(
                    f'Unexpected variable name "{var_name}" assigned from {FN_CALL_EXPRESSION}. '
                    'The standard name is "infos".',
                    file=nasl_file,
                    plugin=self.name,
                )

        if not found_vars:
            yield LinterError(
                f"Missing assignment from {FN_CALL_EXPRESSION}. "
                'The result must be assigned to a variable named "infos".',
                file=nasl_file,
                plugin=self.name,
            )
            return

        for var_name in found_vars:
            access_re = re.compile(rf"\b{var_name}\s*\[(?P<key>[^\]]+)\]")
            for match in access_re.finditer(clean_content):
                key = match.group("key").strip(" \"'")

                if key not in ALLOWED_KEYS:
                    yield LinterError(
                        f'Usage of {var_name} array with invalid key "{key}". '
                        f"Allowed keys are: {', '.join(ALLOWED_KEYS)}.",
                        file=nasl_file,
                        plugin=self.name,
                    )
