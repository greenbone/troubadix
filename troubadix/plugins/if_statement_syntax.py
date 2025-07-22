# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


from pathlib import Path
from typing import Iterator

from troubadix.helper.if_block_parser import IfErrorType, find_if_statements
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
                self._format_error_message(error),
                file=nasl_file,
                plugin=self.name,
            )

    def _format_error_message(self, error):
        match error.error_type:
            case IfErrorType.UNCLOSED_IF_CONDITION:
                return (
                    f"Unclosed parenthesis in if condition at line {error.line}"
                )
            case IfErrorType.UNCLOSED_IF_BODY:
                return f"Unclosed brace in if body at line {error.line}"
            case IfErrorType.MISSING_IF_BODY:
                return f"Missing statement or body after if condition at line {error.line}"
            case IfErrorType.IF_TERMINATED_AFTER_CONDITION:
                return (
                    f"Semicolon after if condition at line {error.line}"
                    " causes if to terminate early."
                    " Following block will always execute."
                )
            case IfErrorType.MISSING_IF_EXPRESSION:
                return f"Missing expression after if condition at line {error.line}"
            case _:
                return f"Unknown if statement syntax error at line {error.line}"
