# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Helper for parsing if blocks and single-expression if statements in NASL files."""

from dataclasses import dataclass

from troubadix.helper.text_utils import (
    StringState,
    index_to_linecol,
)

# Brace pairings
CONDITION_BRACES = ("(", ")")
BLOCK_BRACES = ("{", "}")


@dataclass
class IfStatement:
    if_start: int
    if_end: int
    condition_start: int
    condition_end: int
    statement_start: int
    statement_end: int
    condition: str
    statement: str


class IfParser:
    """Parser for if statements in NASL files."""

    def __init__(self, file_content: str):
        self.file_content = file_content

    def find_if_statements(self) -> list[IfStatement]:
        """Parse the file to find all if statements (blocks and single expressions)."""
        results: list[IfStatement] = []
        starts = self._find_condition_starts()
        if not starts:
            return results

        for if_start, opening_brace in starts:
            line, _ = index_to_linecol(self.file_content, if_start)

            condition_end = self._find_closing_brace(
                opening_brace, CONDITION_BRACES, line
            )
            condition = self.file_content[
                opening_brace + 1 : condition_end
            ].strip()
            statement_pos = self._find_statement_start(condition_end, line)

            if self.file_content[statement_pos] == "{":
                # Block statement
                block_end = self._find_closing_brace(
                    statement_pos, BLOCK_BRACES, line
                )
                if_end = block_end + 1
                statement_start = statement_pos + 1
                statement_end = block_end
                statement = self.file_content[
                    statement_pos + 1 : block_end
                ].strip()
            else:
                # Single expression
                expression_end = self._find_expression_end(statement_pos, line)
                if_end = expression_end + 1
                statement_start = statement_pos
                statement_end = expression_end
                statement = self.file_content[
                    statement_pos:expression_end
                ].strip()

            results.append(
                IfStatement(
                    if_start=if_start,
                    if_end=if_end,
                    condition_start=opening_brace + 1,
                    condition_end=condition_end,
                    statement_start=statement_start,
                    statement_end=statement_end,
                    condition=condition,
                    statement=statement,
                )
            )

        return results

    def _find_closing_brace(
        self,
        start_pos: int,
        brace_pair: tuple[str, str],
        line: int,
    ) -> int:
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
                    return i

        # Generate appropriate error message based on brace type
        if opening_brace == "(":
            raise ValueError(
                f"Unclosed parenthesis in if statement at line {line}"
            )
        elif opening_brace == "{":
            raise ValueError(f"Unclosed brace in if statement at line {line}")
        else:
            raise ValueError(
                f"Unclosed {opening_brace} in if statement at line {line}"
            )

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

    def _find_statement_start(self, condition_end: int, line: int) -> int:
        """Find the start of the statement after the condition (next non-whitespace character)."""
        pos = condition_end + 1
        while pos < len(self.file_content) and self.file_content[pos].isspace():
            pos += 1

        if pos >= len(self.file_content):
            raise ValueError(
                f"Missing statement after if condition at line {line}"
            )

        if self.file_content[pos] == ";":
            raise ValueError(
                f"Semicolon after if condition at line {line} makes following block "
                f"always execute. Remove semicolon to fix."
            )

        return pos

    def _find_expression_end(self, expression_start: int, line: int) -> int:
        """Find the end of a single expression (semicolon outside of strings)."""
        string_state = StringState()

        for i in range(expression_start, len(self.file_content)):
            char = self.file_content[i]
            string_state.process_next_char(char)
            if not string_state.in_string and char == ";":
                return i

        raise ValueError(
            f"Missing expression after if condition at line {line}"
        )


# Wrapper function to maintain backward compatibility
def find_if_statements(file_content: str) -> list[IfStatement]:
    """Parse a file to find all if statements (blocks and single expressions)."""
    parser = IfParser(file_content)
    return parser.find_if_statements()
