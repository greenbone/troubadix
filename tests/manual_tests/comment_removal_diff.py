# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

import sys

from troubadix.helper import CURRENT_ENCODING
from troubadix.helper.remove_comments import remove_comments


# poetry run python tests/manual_tests/comment_removal_diff.py <path_to_nasl_file>
def test_comment_removal(input_file):
    """
    Test the remove_comments function and show all lines with their status.

    Args:
        input_file: Path to the NASL file to test
    """
    try:
        with open(input_file, "r", encoding=CURRENT_ENCODING) as f:
            original_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    processed_content = remove_comments(original_content)

    original_lines = original_content.splitlines()
    processed_lines = processed_content.splitlines()

    print("\nFull comparison between original and processed file:")
    print("----------------------------------------------------")

    max_len = max(len(original_lines), len(processed_lines))

    for i in range(max_len):
        if i < len(original_lines) and i < len(processed_lines):
            if original_lines[i] == processed_lines[i]:
                status = "  "  # Unchanged
            else:
                status = "! "  # Changed
            print(f"{i + 1:4d} {status}{original_lines[i]}")
            if status == "! ":
                print(f"     -> {processed_lines[i]}")

    print("\nSummary:")
    print(f"Original file lines: {len(original_lines)}")
    print(f"Processed file lines: {len(processed_lines)}")

    comment_lines = 0
    for line in original_lines:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            comment_lines += 1
    print(f"Full-line comments: {comment_lines}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nasl_file>")
        sys.exit(1)

    test_comment_removal(sys.argv[1])
