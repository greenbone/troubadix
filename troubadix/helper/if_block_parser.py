# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Helper for parsing if blocks and single-expression if statements in NASL files."""

from dataclasses import dataclass
from enum import Enum

from troubadix.helper.text_utils import (
    StringState,
    index_to_linecol,
)

# Brace pairings
CONDITION_BRACES = ("(", ")")
BODY_BRACES = ("{", "}")


@dataclass
class IfStatement:
    if_start: int
    if_end: int
    condition_start: int
    condition_end: int
    outcome_start: int
    outcome_end: int
    condition: str
    outcome: str


class IfErrorType(Enum):
    UNCLOSED_CONDITION = "Unclosed parenthesis in if condition at line {line}"
    UNCLOSED_BODY = "Unclosed brace in if body at line {line}"
    MISSING_OUTCOME = (
        "Missing statement or body after if condition at line {line}"
    )
    TERMINATED_AFTER_CONDITION = (
        "Semicolon after if condition at line {line} causes if to terminate early. "
        "Following block will always execute."
    )
    MISSING_STATEMENT = "Missing expression after if condition at line {line}"


@dataclass
class IfParseError:
    line: int
    error_type: IfErrorType


@dataclass
class IfParseResult:
    statements: list[IfStatement]
    errors: list[IfParseError]


class IfParser:
    """Parser for if statements in NASL files."""

    def __init__(self, file_content: str):
        self.file_content = file_content

    def find_if_statements(self) -> IfParseResult:
        """
        Parse the file to find all if statements (blocks and single expressions), collecting errors.

        Example NASL if statements:
            if (x > 0) {
                foo();
            }
            if (y < 5)
              bar();
        """
        results: list[IfStatement] = []
        errors: list[IfParseError] = []
        # Step 1: Find all 'if' condition starts
        starts = self._find_condition_starts()
        if not starts:
            return IfParseResult(results, errors)

        for if_start, opening_brace in starts:
            line, _ = index_to_linecol(self.file_content, if_start)

            # Step 2: Find the end of the condition (the closing parenthesis)
            condition_end, condition_error = self._find_closing_brace(
                opening_brace, CONDITION_BRACES
            )
            if condition_error:
                errors.append(
                    IfParseError(line=line, error_type=condition_error)
                )
                continue
            condition = self.file_content[
                opening_brace + 1 : condition_end
            ].strip()

            # Step 3: Find the start of the outcome (first non-whitespace after condition)
            outcome_start, outcome_error = self._find_outcome_start(
                condition_end
            )
            if outcome_error:
                errors.append(IfParseError(line=line, error_type=outcome_error))
                continue

            # Step 4: Determine if this is a body or single-expression statement
            if self.file_content[outcome_start] == "{":
                # Body: find closing brace for body '}'
                body_end, body_error = self._find_closing_brace(
                    outcome_start, BODY_BRACES
                )
                if body_error:
                    errors.append(
                        IfParseError(line=line, error_type=body_error)
                    )
                    continue
                if_end = body_end + 1
                outcome_start = outcome_start + 1  # exclude opening brace
                outcome_end = body_end
            else:
                # Single statement: find end of statement ';'
                statement_end, statement_error = self._find_statement_end(
                    outcome_start
                )
                if statement_error:
                    errors.append(
                        IfParseError(line=line, error_type=statement_error)
                    )
                    continue
                if_end = statement_end + 1
                outcome_end = statement_end

            outcome = self.file_content[outcome_start:outcome_end].strip()

            results.append(
                IfStatement(
                    if_start=if_start,
                    if_end=if_end,
                    condition_start=opening_brace + 1,
                    condition_end=condition_end,
                    outcome_start=outcome_start,
                    outcome_end=outcome_end,
                    condition=condition,
                    outcome=outcome,
                )
            )

        return IfParseResult(results, errors)

    def _find_closing_brace(
        self,
        start_pos: int,
        brace_pair: tuple[str, str],
    ) -> tuple[int | None, IfErrorType | None]:
        """Find the matching closing brace, with proper error reporting."""
        opening_brace, closing_brace = brace_pair
        open_count = 1
        string_state = StringState()

        for i in range(start_pos + 1, len(self.file_content)):
            char = self.file_content[i]
            string_state.process_next_char(char)

            # Skip characters inside strings
            if string_state.in_string:
                continue

            if char == opening_brace:
                open_count += 1
            elif char == closing_brace:
                open_count -= 1
                if open_count == 0:
                    return i, None

        # Error: unclosed brace
        if opening_brace == "(":
            return None, IfErrorType.UNCLOSED_CONDITION
        else:
            return None, IfErrorType.UNCLOSED_BODY

    def _find_condition_starts(self) -> list[tuple[int, int]]:
        """
        Find starting positions of if conditions in the file content.
        Returns:
            A list of tuples where each tuple contains the start position of the "if" keyword
            and the position of the opening parenthesis.
        """
        starts = []
        string_state = StringState()

        for i, char in enumerate(self.file_content):
            string_state.process_next_char(char)

            # Skip characters inside strings
            if string_state.in_string:
                continue

            # check for if with word boundary, valid: ["if", " if"], not valid: "xif"
            if (
                i == 0 or not self.file_content[i - 1].isalnum()
            ) and self.file_content.startswith("if", i):
                # skip whitespace
                j = i + 2
                while (
                    j < len(self.file_content)
                    and self.file_content[j].isspace()
                ):
                    j += 1
                # check for condition start
                if j < len(self.file_content) and self.file_content[j] == "(":
                    starts.append((i, j))

        return starts

    def _find_outcome_start(
        self, condition_end: int
    ) -> tuple[int | None, IfErrorType | None]:
        """
        Find the start of the outcome/then part after the condition (next non-whitespace character).
        """
        pos = condition_end + 1
        while pos < len(self.file_content) and self.file_content[pos].isspace():
            pos += 1

        if pos >= len(self.file_content):
            return None, IfErrorType.MISSING_OUTCOME

        if self.file_content[pos] == ";":
            return None, IfErrorType.TERMINATED_AFTER_CONDITION

        return pos, None

    def _find_statement_end(
        self, statement_start: int
    ) -> tuple[int | None, IfErrorType | None]:
        """Find the end of a single statement (semicolon outside of strings)."""
        string_state = StringState()

        for i in range(statement_start, len(self.file_content)):
            char = self.file_content[i]
            string_state.process_next_char(char)
            if not string_state.in_string and char == ";":
                return i, None

        return None, IfErrorType.MISSING_STATEMENT


# Wrapper function to maintain backward compatibility
def find_if_statements(file_content: str) -> IfParseResult:
    """Parse a file to find all if statements."""
    parser = IfParser(file_content)
    return parser.find_if_statements()
