import re
from argparse import ArgumentParser, Namespace
from subprocess import CalledProcessError
from typing import List, Set, Tuple

from pontos.terminal.terminal import ConsoleTerminal

from troubadix.argparser import file_type
from troubadix.helper.patterns import _get_special_script_tag_pattern
from troubadix.standalone_plugins.common import get_merge_base, git

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def compare(
    old_content: str, current_content: str
) -> Tuple[List[str], List[str]]:
    old_cves = get_cves_from_content(old_content)
    current_cves = get_cves_from_content(current_content)

    missing_cves = sorted(old_cves.difference(current_cves))
    added_cves = sorted(current_cves.difference(old_cves))

    return missing_cves, added_cves


def get_cves_from_content(content: str) -> Set[str]:
    pattern = _get_special_script_tag_pattern(
        name="cve_id", flags=re.MULTILINE | re.DOTALL
    )
    match = pattern.search(content)
    if not match:
        return set()

    cves = CVE_PATTERN.findall(match.group("value"))
    return set(cves)


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Check for changed CVEs in VTs",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        type=file_type,
        default=[],
        required=True,
        help="List of files to check.",
    )
    parser.add_argument(
        "--start-commit",
        type=str,
        required=False,
        help=(
            "The commit before the changes to check have been introduced. "
            "If the files have been renamed before, choose that commit. "
            "Defaults to the merge-base with main"
        ),
        default=get_merge_base("main", "HEAD"),
    )
    parser.add_argument(
        "--hide-equal",
        action="store_true",
        help="Omit log message, if a file has equal CVEs",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    terminal = ConsoleTerminal()

    terminal.info(
        f"Checking {len(args.files)} file(s) from {args.start_commit} to HEAD"
    )

    for file in args.files:
        try:
            old_content = git("show", f"{args.start_commit}:{file}")
            current_content = git("show", f"HEAD:{file}")
        except CalledProcessError:
            terminal.error(
                f"Could not find {file} at {args.start_commit} or HEAD"
            )
            continue

        missing_cves, added_cves = compare(old_content, current_content)

        if not missing_cves and not added_cves:
            if not args.hide_equal:
                terminal.info(f"{file} has equal CVEs")
            continue

        terminal.warning(f"CVEs for {file} differ")
        if missing_cves:
            terminal.print("Missing CVEs: ", ", ".join(missing_cves))
        if added_cves:
            terminal.print("Added CVEs: ", ", ".join(added_cves))
