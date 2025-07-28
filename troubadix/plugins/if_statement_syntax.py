# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


from pathlib import Path
from typing import Iterator

from troubadix.helper.if_block_parser import find_if_statements
from troubadix.helper.remove_comments import remove_comments
from troubadix.plugin import FileContentPlugin, LinterError, LinterResult


class CheckIfStatementSyntax(FileContentPlugin):
    """Check for syntax errors in if statements.

    This plugin uses the if statement parser to detect common syntax errors such as:
    - Unclosed parentheses in if conditions
    - Unclosed braces in if blocks
    - Missing statements after if conditions
    - Semicolons after if conditions (which make following blocks always execute)
    - Missing semicolons in single-line expressions
    """

    name = "check_if_statement_syntax"

    def check_content(
        self,
        nasl_file: Path,
        file_content: str,
    ) -> Iterator[LinterResult]:
        """Check the file content for if statement syntax errors."""
        # Remove comments to avoid false positives from commented code
        comment_free_content = remove_comments(file_content)

        result = find_if_statements(comment_free_content)
        for error in result.errors:
            yield LinterError(
                error.error_type.value.format(line=error.line),
                file=nasl_file,
                plugin=self.name,
            )
