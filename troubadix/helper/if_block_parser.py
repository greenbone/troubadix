# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Helper for parsing if blocks and single-expression if statements in NASL files."""

from dataclasses import dataclass

from troubadix.helper.text_utils import (
    StringState,
    index_to_linecol,
)


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


def find_if_statements(file_content: str) -> list[IfStatement]:
    """Parse a file to find all if statements (blocks and single expressions)."""
    results: list[IfStatement] = []
    starts = _find_condition_starts(file_content)
    if not starts:
        return results

    for if_start, opening_brace in starts:
        line, _ = index_to_linecol(file_content, if_start)

        condition_end = _find_closing_brace(
            file_content, opening_brace, "(", ")", line
        )
        condition = file_content[opening_brace + 1 : condition_end].strip()
        statement_pos = _find_statement_start(file_content, condition_end, line)

        if file_content[statement_pos] == "{":
            # Block statement
            block_end = _find_closing_brace(
                file_content, statement_pos, "{", "}", line
            )
            if_end = block_end + 1
            statement_start = statement_pos + 1
            statement_end = block_end
            statement = file_content[statement_pos + 1 : block_end].strip()
        else:
            # Single expression
            expression_end = _find_expression_end(
                file_content, statement_pos, line
            )
            if_end = expression_end + 1
            statement_start = statement_pos
            statement_end = expression_end
            statement = file_content[statement_pos:expression_end].strip()

        if_stmt = IfStatement(
            if_start=if_start,
            if_end=if_end,
            condition_start=opening_brace + 1,
            condition_end=condition_end,
            statement_start=statement_start,
            statement_end=statement_end,
            condition=condition,
            statement=statement,
        )

        results.append(if_stmt)

    return results


def _find_closing_brace(
    file_content: str,
    start_pos: int,
    opening_brace: str,
    closing_brace: str,
    line: int,
) -> int:
    """Find the matching closing brace, with proper error reporting."""
    open_count = 1
    string_state = StringState()

    for i in range(start_pos + 1, len(file_content)):
        char = file_content[i]
        string_state.process_next_char(char)
        # Only count braces when not in a string
        if not string_state.in_string:
            if char == opening_brace:
                open_count += 1
            elif char == closing_brace:
                open_count -= 1
                if open_count == 0:
                    return i

    # Generate appropriate error message based on brace type
    if opening_brace == "(":
        raise ValueError(f"Unclosed parenthesis in if statement at line {line}")
    elif opening_brace == "{":
        raise ValueError(f"Unclosed brace in if statement at line {line}")
    else:
        raise ValueError(
            f"Unclosed {opening_brace} in if statement at line {line}"
        )


def _find_condition_starts(file_content: str) -> list[tuple[int, int]]:
    """
    Find starting positions of if conditions in the file content.
    Args:
        file_content: The content of the NASL file to analyze
    Returns:
        A list of tuples where each tuple contains the start position of the "if" keyword
        and the position of the opening parenthesis.
    """
    starts = []
    string_state = StringState()

    for i, char in enumerate(file_content):
        string_state.process_next_char(char)

        # check only outside of strings
        if not string_state.in_string:
            # check for if with word boundary, valid: ["if", " if"], not valid: "xif"
            if (
                i == 0 or not file_content[i - 1].isalnum()
            ) and file_content.startswith("if", i):
                # skip whitespace
                j = i + 2
                while j < len(file_content) and file_content[j].isspace():
                    j += 1
                # check for condition start
                if j < len(file_content) and file_content[j] == "(":
                    starts.append((i, j))

    return starts


def _find_statement_start(
    file_content: str, condition_end: int, line: int
) -> int:
    """Find the start of the statement after the condition (next non-whitespace character)."""
    pos = condition_end + 1
    while pos < len(file_content) and file_content[pos].isspace():
        pos += 1

    if pos >= len(file_content):
        raise ValueError(f"Missing statement after if condition at line {line}")

    if file_content[pos] == ";":
        raise ValueError(
            f"Semicolon after if condition at line {line} makes following block "
            f"always execute. Remove semicolon to fix."
        )

    return pos


def _find_expression_end(
    file_content: str, expression_start: int, line: int
) -> int:
    """Find the end of a single expression (semicolon outside of strings)."""
    string_state = StringState()

    for i in range(expression_start, len(file_content)):
        char = file_content[i]
        string_state.process_next_char(char)
        if not string_state.in_string and char == ";":
            return i

    raise ValueError(f"Missing expression after if condition at line {line}")
