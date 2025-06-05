from troubadix.helper.text_utils import handle_string_context


def remove_comments(file_content: str) -> str:
    """
    Remove all commented portions from file content while preserving string literals.

    This function:
    1. Removes content from lines that start with '#' (also after whitespace)
    2. For lines with inline comments, keeps only the content before the '#'
    3. Preserves '#' characters within string literals
    4. Maintains original line numbers by keeping empty lines
    5. Handles multiline strings

    Args:
        file_content: String containing the full file content

    Returns:
        String with comments removed
    """
    lines = file_content.splitlines()
    clean_lines = []

    in_single_quote = False
    in_double_quote = False
    escape_next = False

    for line in lines:
        # Skip lines that are entirely comments (after whitespace) if not in a string
        if not (
            in_single_quote or in_double_quote
        ) and line.lstrip().startswith("#"):
            clean_lines.append("")  # Keep empty line to maintain line numbers
            continue

        # Handle inline comments (but respect strings)
        processed_line = ""

        for char in line:
            escape_next, in_double_quote, in_single_quote = (
                handle_string_context(
                    char, escape_next, in_double_quote, in_single_quote
                )
            )
            # Check for comment outside of strings
            if char == "#" and not in_single_quote and not in_double_quote:
                break

            processed_line += char

        clean_lines.append(processed_line)

    return "\n".join(clean_lines)
