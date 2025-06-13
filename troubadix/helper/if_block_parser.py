# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

"""Helper for parsing if blocks and single-expression if statements in NASL files."""

from dataclasses import dataclass

from troubadix.helper.text_utils import (
    handle_string_context,
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


def find_closing_brace(
    file_content: str, start_pos: int, opening_brace: str, closing_brace
) -> int:
    open_count = 1
    in_double_quote = False
    in_single_quote = False
    escape_next = False
    for i in range(start_pos + 1, len(file_content)):
        char = file_content[i]
        escape_next, in_double_quote, in_single_quote = handle_string_context(
            char, escape_next, in_double_quote, in_single_quote
        )
        # Only count parentheses when not in a string
        if not in_double_quote and not in_single_quote:
            if char == opening_brace:
                open_count += 1
            elif char == closing_brace:
                open_count -= 1
                if open_count == 0:
                    return i

    # If we couldn't find a matching parenthesis
    line, col = index_to_linecol(file_content, start_pos)
    raise ValueError(f"Unclosed {opening_brace} in if statement in line {line}")


def find_condition_starts(file_content: str) -> list[tuple[int, int]]:
    """
    Find starting positions of if conditions in the file content.
    Args:
        file_content: The content of the NASL file to analyze
    Returns:
        A list of tuples where each tuple contains the start position of the "if" keyword
        and the position of the opening parenthesis.
    """
    starts = []
    in_double_quote = False
    in_single_quote = False

    escape_next = False

    for i, char in enumerate(file_content):
        escape_next, in_double_quote, in_single_quote = handle_string_context(
            char, escape_next, in_double_quote, in_single_quote
        )

        # check only outside of strings
        if not in_double_quote and not in_single_quote:
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


def find_if_statements(file_content: str) -> list[IfStatement]:
    """
    Parse a file to find all if statements (blocks and single expressions).

    Args:
        file_content: The content of the NASL file to analyze

    Returns:
        A list of IfBlock and IfSingleExpression objects containing the parsed information

    Raises:
        ValueError: When there are syntax errors in if statements
    """
    results: list[IfStatement] = []
    # Find potential if statement starts
    starts = find_condition_starts(file_content)
    if not starts:
        return results

    for if_start, opening_brace in starts:
        line, position = index_to_linecol(file_content, if_start)

        # Find the matching closing parenthesis
        try:
            condition_end = find_closing_brace(
                file_content, opening_brace, "(", ")"
            )
        except ValueError:
            raise ValueError(
                f"Unclosed parenthesis in if statement at line {line}, position {position}"
            )

        # Extract the condition
        condition = file_content[opening_brace + 1 : condition_end].strip()

        # Skip whitespace after the closing parenthesis
        pos = condition_end + 1
        while pos < len(file_content) and file_content[pos].isspace():
            pos += 1

        if pos >= len(file_content):
            raise ValueError(
                f"Missing statement after if condition at line {line}, position {position}"
            )

        # Check for useless semicolon termination
        if file_content[pos] == ";":
            raise ValueError(
                "Semicolon after if condition causes following"
                f" block to always execute at line {line}, position {position}"
            )

        # Check if there's a block
        if file_content[pos] == "{":
            try:
                # This is a block-style if
                block_end = find_closing_brace(file_content, pos, "{", "}")
            except ValueError:
                raise ValueError(
                    f"Unclosed brace in if statement at line {line}, position {position}"
                )

            results.append(
                IfStatement(
                    if_start=if_start,
                    if_end=block_end + 1,
                    condition_start=opening_brace + 1,
                    condition_end=condition_end,
                    statement_start=pos + 1,
                    statement_end=block_end,
                    condition=condition,
                    statement=file_content[pos + 1 : block_end].strip(),
                )
            )
        else:
            # This is a single-expression if
            expression_start = pos
            expression_end = expression_start

            in_double_quote = False
            in_single_quote = False
            escape_next = False

            # Find where the expression ends (semicolon outside of strings)
            for i in range(expression_start, len(file_content)):
                char = file_content[i]
                escape_next, in_double_quote, in_single_quote = (
                    handle_string_context(
                        char, escape_next, in_double_quote, in_single_quote
                    )
                )
                # Only detect semicolons when not in a string
                if not in_double_quote and not in_single_quote and char == ";":
                    expression_end = i
                    break

            if expression_end <= expression_start:
                raise ValueError(
                    f"Missing expression after if condition at line {line}, position {position}"
                )

            expression = file_content[expression_start:expression_end].strip()
            results.append(
                IfStatement(
                    if_start=if_start,
                    if_end=expression_end + 1,
                    condition_start=opening_brace + 1,
                    condition_end=condition_end,
                    statement_start=expression_start,
                    statement_end=expression_end,
                    condition=condition,
                    statement=expression,
                )
            )

    return results
