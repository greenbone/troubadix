#!/usr/bin/env python3

""" This is the master script for all the local checks that need to be executed prior to committing added/modified/deleted VTs to the repository
Each individual check will generate an error message if a specific VT fails to meet the test criteria

Returns:
    printed strings: A list of all errors including the specific VTs they occurred in
        If 'DEBUG' is set, additional information will be printed out. The VT may be committed though, as the check succeeded

"""

import subprocess, sys, re, os, getopt
from datetime import datetime
from sys import version_info, exit

from steps import *

if version_info < (3,):
    exit("Python < 3 is not supported")

DEBUG = True
FULL = False
SKIP_OID = False
start_dir = "./"
chosen_tests = ["all"]
excluded_tests = []
recursive = True
cur_recursion_level = 0
include_regex = ""
exclude_regex = ""
staged_only = False
use_commit_range = False
passed_commit_range = ""

# nb: Use vt_list for enumerating down below, the inc_list and dir_list are only used for the openvas-nasl-lint step in the "FULL" case.
# nasl_list, nasl_added_list, nasl_mod_list, inc_added_list and inc_mod_list are only used for the stats.
vt_list = []
inc_list = []
nasl_list = []
dir_list = []
nasl_add_list = []
nasl_mod_list = []
nasl_rnm_list = []
inc_add_list = []
inc_mod_list = []
inc_rnm_list = []

# The list of current valid tests which can be chosen with the -t/--test parameter.
supported_tests = [
    "all",
    "encoding",
    "cve_format",
    "cvss_format",
    "creation_date",
    "lint",
    "display",
    "mandatory_script_calls",
    "mandatory_script_tags",
    "solution_type",
    "family",
    "qod",
    "codespell",
    "dependencies",
    "valid_script_tag",
    "duplicate_oid",
    "illegal_characters",
    "deprecated_functions",
    "solution_text",
    "newlines",
    "copyright",
    "scm_tags",
    "script_tag_newlines",
    "badwords",
    "overlong_script_tags",
    "tbd_todo",
    "recommended_script_calls",
    "http_link_in_tag",
    "nvd_mitre_link_in_xref",
    "trail_lead_nts_in_tag",
    "valid_url_script_xref",
    "category",
    "dup_script_tags",
    "missing_desc_exit",
    "misuse_forking_funcs",
    "set_get_kb_calls",
    "empty_values",
    "valid_script_tag_names",
    "log_message_with_severity",
    "security_message_without_severity",
    "valid_script_add_preference_type",
    "var_assign_in_if",
    "dependency_category_order",
    "valid_oid",
    "misplaced_compare_in_if",
    "deprecated_dependency",
    "missing_solution_tag",
    "check_for_tabs",
    "trailing_spaces_tabs",
    "check_updated_date_version",
    "check_vt_placement",
    "get_kb_on_services",
    "changed_oid",
    "prod_svc_detect_in_vulnvt",
    "grammar",
    "doubled_end_point",
]


def help():
    print(
        "Usage: "
        + sys.argv[0]
        + " [-h --help, -f --full-run, --no-debug, --staged-only, --commit-range <range>, --skip-dup-oid, -s <startdir> --start-dir <startdir>, --non-recursive, --file-include-regex <regex>, --file-exclude-regex <regex>, -t <testname(s)>, --tests <testname(s)>]"
    )
    print("\nParameters:")
    print("\t-h, --help: This help output")
    print(
        "\t-f, --full-run: Checking the complete VT directory and not only the added/changed scripts"
    )
    print("\t--no-debug: Disables the DEBUG output")
    print(
        "\t--staged-only: Only run against files which are 'staged/added' in git"
    )
    print(
        "\t--commit-range: (optional, only used if -f / --full-run wasn't passed) Allows to specify a git commit range (e.g. '$commit-hash1...$commit-hash2' or 'HEAD~1') to run the QA test against."
    )
    print("\t--skip-dup-oid: Disables the check for duplicated OIDs in VTs")
    print(
        "\t-s, --startdir <startdir>: (optional, defaults to ./) Allows to choose the dir which should be used by the script as a start dir. If no files within this dir where modified -f --full-run needs to be passed"
    )
    print(
        "\t--non-recursive: (optional, only used together with -f, --full-run) Don't run the script recursive from the startdir"
    )
    print(
        "\t--file-include-regex: (optional, only used together with -f, --full-run) Allows to specify a regex (e.g. (suse_|sles)) to limit the 'full' run to specific file names."
    )
    print(
        "\t--file-exclude-regex: (optional, only used together with -f, --full-run) Allows to specify a regex (e.g. (suse_|sles)) to exclude specific file names from the 'full' run."
    )
    supported_tests.sort()
    print(
        "\t--include-tests <testname(s)>: (optional, defaults to all) Allows to choose (as a comma separated string like: encoding,cve_format_error) which tests should be run/used by the script. Currently valid:\n\n\t"
        + ",".join(supported_tests)
    )
    print(
        "\t--exclude-tests <testname(s)>: (optional, needs to be called after --include-tests) Allows to choose (as a comma separated string like: encoding,cve_format_error) which tests should NOT run/used by the script. See include-tests for a list of tests"
    )
    exit()


if len(sys.argv) > 1:
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hfs:",
            [
                "help",
                "full-run",
                "no-debug",
                "staged-only",
                "commit-range=",
                "skip-dup-oid",
                "start-dir=",
                "non-recursive",
                "file-include-regex=",
                "file-exclude-regex=",
                "include-tests=",
                "exclude-tests=",
            ],
        )
    except getopt.GetoptError:
        print(
            "ERROR: Non-existent option given or option requiring an argument is given none. See below for the usage.\n"
        )
        help()
    for opt, arg in opts:
        if opt == "-h" or opt == "--help":
            help()
        elif opt == "-f" or opt == "--full-run":
            FULL = True
        elif opt == "-s" or opt == "--start-dir":
            start_dir = arg
        elif opt == "--no-debug":
            DEBUG = False
        elif opt == "--skip-dup-oid":
            SKIP_OID = True
            excluded_tests.append("duplicate_oid")
        elif opt == "--non-recursive":
            recursive = False
        elif opt == "--file-include-regex":
            include_regex = arg
        elif opt == "--file-exclude-regex":
            exclude_regex = arg
        elif opt == "--staged-only":
            staged_only = True
        elif opt == "--commit-range":
            use_commit_range = True
            passed_commit_range = arg
        elif opt == "--include-tests":
            chosen_tests = arg.split(",")
            if len(chosen_tests) < 1:
                print(
                    "ERROR: Invalid list of tests to run given to the --include-tests parameter. See below for the usage.\n"
                )
                help()
            for chosen_test in chosen_tests:
                if chosen_test not in supported_tests:
                    print(
                        "ERROR: Invalid test '"
                        + chosen_test
                        + "' given to the --include-tests parameter. See below for the usage / available tests.\n"
                    )
                    help()
        elif opt == "--exclude-tests":
            excluded_tests = arg.split(",")
            if len(excluded_tests) < 1:
                print(
                    "ERROR: Invalid list of tests to run given to the --exclude-tests parameter. See below for the usage.\n"
                )
                help()
            for excluded_test in excluded_tests:
                if excluded_test not in supported_tests:
                    print(
                        "ERROR: Invalid test '"
                        + excluded_test
                        + "' given to the --include-tests parameter. See below for the usage / available tests.\n"
                    )
                    help()
    for chosen_test in chosen_tests:
        if chosen_test in excluded_tests:
            print(
                "ERROR: Test '"
                + chosen_test
                + "' given to the --include-tests parameter which was also passed to the --exclude-tests parameter.\n"
            )
            exit()

vt_var_set = True
cwd = os.getcwd()


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


deprecated_env_var_found = False

try:
    vtdir = os.environ["NVTDIR"]
    deprecated_env_var_found = True
except:
    try:
        vtdir = os.environ["VTDIR"]
    except:
        vt_var_set = False
        print(
            "Please set the environment variable '$VTDIR' (e.g. in your .bashrc) to your local openvas-nasl scripts directory!\r\n"
        )

if deprecated_env_var_found:
    print(
        "Deprecated '$NVTDIR' environment variable found. Please rename the variable to '$VTDIR'"
    )

if not vt_var_set:
    print(
        "Global '$VTDIR' variable not set. Trying to locate the scripts folder manually ..."
    )
    foundvtdir = False
    for root, dirs, files in os.walk(cwd):
        for dir_ in dirs:
            if dir_ == "nasl":
                vtdir = cwd + "/" + dir_
                print("NASL directory found under: " + vtdir)
                foundvtdir = True
                break
    if not foundvtdir:
        print(
            "Global '$VTDIR' variable is not set and nasl folder not found manually. Exiting..."
        )
        exit(-1)

# Switch from current working directory to scripts/ directory so that subprocesses like 'openvas-nasl-lint' don't fail
os.chdir(vtdir)

if FULL:
    for root, dirs, files in os.walk(start_dir):
        if not recursive and cur_recursion_level >= 1:
            break
        cur_recursion_level += 1
        for file_name in files:
            file_name_lower = str(file_name.lower())
            if file_name_lower.endswith(".nasl") or file_name_lower.endswith(
                ".inc"
            ):
                if len(include_regex) > 0:
                    include_file = re.search(include_regex, file_name)
                    if include_file is None:
                        continue
                if len(exclude_regex) > 0:
                    exclude_file = re.search(exclude_regex, file_name)
                    if exclude_file is not None:
                        continue
                vt_list.append(os.path.join(root, file_name))
                # nb: See comment about inc_list above
                if file_name_lower.endswith(".inc"):
                    inc_list.append(os.path.join(root, file_name))
                # nb: Only for the stats
                if file_name_lower.endswith(".nasl"):
                    nasl_list.append(os.path.join(root, file_name))

    dir_list.append(start_dir)
    if recursive:
        for root, dirs, files in os.walk(start_dir):
            for dir_name in dirs:
                dir_list.append(os.path.join(root, dir_name))

    print(
        "\r\nNote: Checking the complete VT directory requested. Skip the duplicate OID check for now...\r\n"
    )

    no_files_found = False
    vt_list_len = len(vt_list)
    stats_report = "======= BEGIN STATS =======\r\n"
    if vt_list_len == 0:
        no_files_found = True
        stats_report += (
            'No scripts detected within the passed "'
            + start_dir
            + '" folder found. QA will exit!\r\n'
        )

    if not no_files_found:
        stats_report += "Started tests:  " + ", ".join(chosen_tests) + "\r\n"

        if len(excluded_tests) > 0:
            stats_report += (
                "Excluded tests: " + ", ".join(excluded_tests) + "\r\n"
            )

        stats_report += (
            "Checked files:  "
            + str(len(nasl_list))
            + " (.nasl), "
            + str(len(inc_list))
            + " (.inc)\r\n"
        )

    stats_report += "======== END STATS ========\r\n\r\n"
    print(stats_report)

    if no_files_found:
        print("No files Found ...")
        exit(0)

else:

    os.chdir("../")

    # Get all added/modified/deleted scripts
    if staged_only:
        added = (
            subprocess_cmd(
                "git --no-pager diff --cached --name-status | egrep '\.(nasl|inc)$' | awk '/^\s*A/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        modified = (
            subprocess_cmd(
                "git --no-pager diff --cached --name-status | egrep '\.(nasl|inc)$' | awk '/^\s*M/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        renamed = (
            subprocess_cmd(
                "git --no-pager diff --cached --name-status | egrep '\.(nasl|inc)$' | awk '/^\s*R/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
    elif use_commit_range:
        added = (
            subprocess_cmd(
                "git --no-pager diff --name-status "
                + passed_commit_range
                + " | egrep '\.(nasl|inc)$' | awk '/^\s*A/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        modified = (
            subprocess_cmd(
                "git --no-pager diff --name-status "
                + passed_commit_range
                + " | egrep '\.(nasl|inc)$' | awk '/^\s*M/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        renamed = (
            subprocess_cmd(
                "git --no-pager diff --name-status "
                + passed_commit_range
                + " | egrep '\.(nasl|inc)$' | awk '/^\s*R/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
    else:
        added = (
            subprocess_cmd(
                "git -c color.status=false --no-pager status --short | egrep '\.(nasl|inc)$' | awk '/^\s*A/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        modified = (
            subprocess_cmd(
                "git -c color.status=false --no-pager status --short | egrep '\.(nasl|inc)$' | awk '/^\s*M/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )
        renamed = (
            subprocess_cmd(
                "git -c color.status=false --no-pager status --short | egrep '\.(nasl|inc)$' | awk '/^\s*R/ { print $NF ; }' | sed 's/^nasl\///'"
            )
            .decode("latin-1")
            .splitlines()
        )

    # and concatenate them into a single list
    vt_list = added + modified + renamed
    vt_list_len = len(vt_list)

    no_changes = False
    if SKIP_OID:
        print("\r\nNote: Skip of the duplicate OID check requested.\r\n")
    stats_report = "======= BEGIN STATS =======\r\n"
    if vt_list_len == 0:
        no_changes = True
        stats_report += 'No new or modified files detected via "git status". QA will exit!\r\n'

    if not no_changes:
        for file in added:
            if file == "":
                continue
            file_lower = str(file.lower())
            if file_lower.endswith(".nasl"):
                nasl_add_list.append(file)
            elif file_lower.endswith(".inc"):
                inc_add_list.append(file)

        for file in modified:
            if file == "":
                continue
            file_lower = str(file.lower())
            if file_lower.endswith(".nasl"):
                nasl_mod_list.append(file)
            elif file_lower.endswith(".inc"):
                inc_mod_list.append(file)

        for file in renamed:
            if file == "":
                continue
            file_lower = str(file.lower())
            if file_lower.endswith(".nasl"):
                nasl_rnm_list.append(file)
            elif file_lower.endswith(".inc"):
                inc_rnm_list.append(file)

        stats_report += "Started tests:  " + ", ".join(chosen_tests) + "\r\n"

        if len(excluded_tests) > 0:
            stats_report += (
                "Excluded tests: " + ", ".join(excluded_tests) + "\r\n"
            )

        if len(passed_commit_range) > 0:
            stats_report += (
                "Passed git\ncommit range:   " + passed_commit_range + "\r\n"
            )

        stats_report += (
            "Added files:    "
            + str(len(nasl_add_list))
            + " (.nasl), "
            + str(len(inc_add_list))
            + " (.inc)\r\n"
        )
        stats_report += (
            "Modified files: "
            + str(len(nasl_mod_list))
            + " (.nasl), "
            + str(len(inc_mod_list))
            + " (.inc)\r\n"
        )
        stats_report += (
            "Renamed files:  "
            + str(len(nasl_rnm_list))
            + " (.nasl), "
            + str(len(inc_rnm_list))
            + " (.inc)\r\n"
        )
        if vt_list_len > 5:
            stats_report += "(output shortened)\r\n"
        else:
            stats_report += "\r\n\r\n"
            for a in added:
                stats_report += "A " + str(a) + "\r\n"

            for m in modified:
                stats_report += "M " + str(m) + "\r\n"

            for r in renamed:
                stats_report += "R " + str(r) + "\r\n"

    stats_report += "======== END STATS ========\r\n\r\n"
    print(stats_report)

    if no_changes:
        exit(0)

os.chdir(vtdir)

test_success = True
has_warning = False

encoding_error = False
encoding_error_text = ""

cve_format_error = False
cve_format_error_text = ""

cvss_format_error = False
cvss_format_error_text = ""

creation_date_error = False
creation_date_error_text = ""

lint_error = False
lint_error_text = ""

display_error = False
display_error_text = ""

mandatory_script_calls_error = False
mandatory_script_calls_error_text = ""

mandatory_script_tags_error = False
mandatory_script_tags_error_text = ""

solution_type_error = False
solution_type_error_text = ""

family_error = False
family_error_text = ""

qod_error = False
qod_error_text = ""

codespell_error = False
codespell_error_text = ""

dependencies_error = False
dependencies_error_text = ""

valid_script_tag_error = False
valid_script_tag_error_text = ""

duplicate_oid_error = False
duplicate_oid_error_text = ""

illegal_characters_error = False
illegal_characters_error_text = ""

deprecated_functions_error = False
deprecated_functions_error_text = ""

solution_text_error = False
solution_text_error_text = ""

newlines_error = False
newlines_error_text = ""

copyright_year_error = False
copyright_year_error_text = ""

copyright_text_error = False
copyright_text_error_text = ""

scm_tags_error = False
scm_tags_error_text = ""

script_tag_newlines_error = False
script_tag_newlines_error_text = ""

badwords_error = False
badwords_error_text = ""

overlong_script_tags_error = False
overlong_script_tags_error_text = ""

http_link_in_tag_error = False
http_link_in_tag_error_text = ""

nvd_mitre_link_in_xref_error = False
nvd_mitre_link_in_xref_error_text = ""

trail_lead_nts_in_tag_error = False
trail_lead_nts_in_tag_error_text = ""

valid_url_script_xref_error = False
valid_url_script_xref_error_text = ""

category_error = False
category_error_text = ""

duplicate_script_tags_error = False
duplicate_script_tags_error_text = ""

missing_desc_exit_error = False
missing_desc_exit_error_text = ""

misuse_forking_funcs_error = False
misuse_forking_funcs_error_text = ""

set_get_kb_calls_error = False
set_get_kb_calls_error_text = ""

empty_value_error = False
empty_value_error_text = ""

valid_script_tag_names_error = False
valid_script_tag_names_error_text = ""

using_log_message_with_severity_error = False
using_log_message_with_severity_error_text = ""

using_security_message_without_severity_error = False
using_security_message_without_severity_error_text = ""

valid_script_add_preference_type_error = False
valid_script_add_preference_type_error_text = ""

var_assign_in_if_error = False
var_assign_in_if_error_text = ""

dependency_category_order_error = False
dependency_category_order_error_text = ""

valid_oid_error = False
valid_oid_error_text = ""

misplaced_compare_in_if_error = False
misplaced_compare_in_if_error_text = ""

deprecated_dependency_error = False
deprecated_dependency_error_text = ""

missing_solution_tag_error = False
missing_solution_tag_error_text = ""

check_for_tabs_error = False
check_for_tabs_error_text = ""

trailing_spaces_tabs_error = False
trailing_spaces_tabs_error_text = ""

check_updated_date_version_error = False
check_updated_date_version_error_text = ""

check_vt_placement_error = False
check_vt_placement_error_text = ""

get_kb_on_services_error = False
get_kb_on_services_error_text = ""

changed_oid_warning = False
changed_oid_warning_text = ""

prod_svc_detect_in_vulnvt_error = False
prod_svc_detect_in_vulnvt_error_text = ""

grammar_error = False
grammar_error_text = ""

doubled_end_point_error = False
doubled_end_point_error_text = ""

debug_messages = ""

for file in vt_list:

    # Empty filename should be covered by the git stats above, but checking it again to make sure
    if file == "" or "template.nasl" in file:
        continue
    file_lower = str(file.lower())
    if not file_lower.endswith(".nasl") and not file_lower.endswith(".inc"):
        continue

    # just a workaround for the files placed in vts/attic/scripts and not in vts/scripts
    if "attic/scripts/" in file:
        file = "../" + file

    encoding_result = 0, 0
    cve_format_result = 0, 0
    cvss_format_result = 0, 0
    creation_date_result = 0, 0
    lint_result = 0, 0
    display_result = 0, 0
    display_result_debug = 0, 0
    mandatory_script_calls_result = 0, 0
    mandatory_script_tags_result = 0, 0
    solution_type_result = 0, 0
    family_result = 0, 0
    qod_result = 0, 0
    codespell_result = 0, 0
    recommended_script_calls_result = 0, 0
    dependencies_result = 0, 0
    valid_script_tag_result = 0, 0
    duplicate_oid_result = 0, 0
    illegal_characters_result = 0, 0
    deprecated_functions_result = 0, 0
    solution_text_result = 0, 0
    newlines_result = 0, 0
    tbd_todo_result = 0, 0
    copyright_year_result = 0, 0
    copyright_text_result = 0, 0
    scm_tags_result = 0, 0
    script_tag_newlines_result = 0, 0
    badwords_result = 0, 0
    overlong_script_tags_result = 0, 0
    http_link_in_tag_result = 0, 0
    nvd_mitre_link_in_xref_result = 0, 0
    trail_lead_nts_in_tag_result = 0, 0
    valid_url_script_xref_result = 0, 0
    category_result = 0, 0
    duplicate_script_tags_result = 0, 0
    missing_desc_exit_result = 0, 0
    misuse_forking_funcs_result = 0, 0
    set_get_kb_calls_result = 0, 0
    empty_value_result = 0, 0
    valid_script_tag_names_result = 0, 0
    using_log_message_with_severity_result = 0, 0
    using_security_message_without_severity_result = 0, 0
    valid_script_add_preference_type_result = 0, 0
    var_assign_in_if_result = 0, 0
    dependency_category_order_result = 0, 0
    valid_oid_result = 0, 0
    misplaced_compare_in_if_result = 0, 0
    deprecated_dependency_result = 0, 0
    missing_solution_tag_result = 0, 0
    check_for_tabs_result = 0, 0
    trailing_spaces_tabs_result = 0, 0
    check_updated_date_version_result = 0, 0
    check_vt_placement_result = 0, 0
    get_kb_on_services_result = 0, 0
    changed_oid_result = 0, 0
    prod_svc_detect_in_vulnvt_result = 0, 0
    grammar_result = 0, 0
    doubled_end_point_result = 0, 0

    # Those checks are only valid for .nasl files and not the includes ending with .inc
    if file_lower.endswith(".nasl"):

        if (
            "cve_format" not in excluded_tests
            and "all" in chosen_tests
            or "cve_format" in chosen_tests
        ):
            cve_format_result = check_cve_format.is_cve_format_correct(file)

        if (
            "cvss_format" not in excluded_tests
            and "all" in chosen_tests
            or "cvss_format" in chosen_tests
        ):
            cvss_format_result = check_cvss_format.is_cvss_format_correct(file)

        if (
            "creation_date" not in excluded_tests
            and "all" in chosen_tests
            or "creation_date" in chosen_tests
        ):
            creation_date_result = check_creation_date.is_creation_date_correct(
                file
            )

        if (
            "mandatory_script_calls" not in excluded_tests
            and "all" in chosen_tests
            or "mandatory_script_calls" in chosen_tests
        ):
            mandatory_script_calls_result = (
                check_script_calls_and_tags.has_all_mandatory_script_calls(file)
            )

        if (
            "recommended_script_calls" not in excluded_tests
            and "all" in chosen_tests
            or "recommended_script_calls" in chosen_tests
        ):
            recommended_script_calls_result = (
                check_script_calls_and_tags.has_recommended_script_calls(file)
            )

        if (
            "mandatory_script_tags" not in excluded_tests
            and "all" in chosen_tests
            or "mandatory_script_tags" in chosen_tests
        ):
            mandatory_script_tags_result = (
                check_script_calls_and_tags.has_all_mandatory_script_tags(file)
            )

        if (
            "solution_type" not in excluded_tests
            and "all" in chosen_tests
            or "solution_type" in chosen_tests
        ):
            solution_type_result = check_solution_type.is_solution_type_correct(
                file
            )

        if (
            "family" not in excluded_tests
            and "all" in chosen_tests
            or "family" in chosen_tests
        ):
            family_result = check_script_family.is_family_correct(file)

        if (
            "qod" not in excluded_tests
            and "all" in chosen_tests
            or "qod" in chosen_tests
        ):
            qod_result = check_qod.is_qod_correct(file)

        if (
            "dependencies" not in excluded_tests
            and "all" in chosen_tests
            or "dependencies" in chosen_tests
        ):
            dependencies_result = check_dependencies.is_dependency_existing(
                file
            )

        if (
            "valid_script_tag" not in excluded_tests
            and "all" in chosen_tests
            or "valid_script_tag" in chosen_tests
        ):
            valid_script_tag_result = (
                check_script_calls_and_tags.has_valid_script_tag_calls(file)
            )

        if (
            "script_tag_newlines" not in excluded_tests
            and "all" in chosen_tests
            or "script_tag_newlines" in chosen_tests
        ):
            script_tag_newlines_result = (
                check_newlines.has_unallowed_newlines_in_script_tags(file)
            )

        # This currently can take some time, so exclude it for now if a full scan is required, until the step is improved
        if not FULL:
            if (
                "duplicate_oid" not in excluded_tests
                and "all" in chosen_tests
                or "duplicate_oid" in chosen_tests
            ):
                duplicate_oid_result = check_duplicate_oid.is_oid_unique(file)

        if (
            "illegal_characters" not in excluded_tests
            and "all" in chosen_tests
            or "illegal_characters" in chosen_tests
        ):
            illegal_characters_result = (
                check_illegal_characters.contains_no_illegal_chars(file)
            )

        if (
            "solution_text" not in excluded_tests
            and "all" in chosen_tests
            or "solution_text" in chosen_tests
        ):
            solution_text_result = (
                check_solution_text.is_using_correct_solution_text(file)
            )

        if "pre2008/" not in file_lower:
            if (
                "copyright" not in excluded_tests
                and "all" in chosen_tests
                or "copyright" in chosen_tests
            ):
                copyright_year_result = check_copyright_year.run(file)

        if (
            "copyright" not in excluded_tests
            and "all" in chosen_tests
            or "copyright" in chosen_tests
        ):
            copyright_text_result = check_copyright_text.run(file)

        if (
            "scm_tags" not in excluded_tests
            and "all" in chosen_tests
            or "scm_tags" in chosen_tests
        ):
            scm_tags_result = check_scm_tags.run(file)

        if (
            "overlong_script_tags" not in excluded_tests
            and "all" in chosen_tests
            or "overlong_script_tags" in chosen_tests
        ):
            overlong_script_tags_result = (
                check_overlong_script_tags.contains_overlong_script_tags(file)
            )

        if (
            "http_link_in_tag" not in excluded_tests
            and "all" in chosen_tests
            or "http_link_in_tag" in chosen_tests
        ):
            http_link_in_tag_result = (
                check_http_links_in_tags.contains_http_link_in_tag(file)
            )

        if (
            "nvd_mitre_link_in_xref" not in excluded_tests
            and "all" in chosen_tests
            or "nvd_mitre_link_in_xref" in chosen_tests
        ):
            nvd_mitre_link_in_xref_result = (
                check_http_links_in_tags.contains_nvd_mitre_link_in_xref(file)
            )

        if (
            "trail_lead_nts_in_tag" not in excluded_tests
            and "all" in chosen_tests
            or "trail_lead_nts_in_tag" in chosen_tests
        ):
            trail_lead_nts_in_tag_result = check_script_calls_and_tags.has_trail_lead_newline_tab_space_tag(
                file
            )

        if (
            "valid_url_script_xref" not in excluded_tests
            and "all" in chosen_tests
            or "valid_url_script_xref" in chosen_tests
        ):
            valid_url_script_xref_result = (
                check_script_calls_and_tags.has_valid_url_script_xref(file)
            )

        if (
            "category" not in excluded_tests
            and "all" in chosen_tests
            or "category" in chosen_tests
        ):
            category_result = check_script_category.is_category_correct(file)

        if (
            "dup_script_tags" not in excluded_tests
            and "all" in chosen_tests
            or "dup_script_tags" in chosen_tests
        ):
            duplicate_script_tags_result = (
                check_duplicated_script_tags.has_duplicate_script_tags(file)
            )

        if (
            "missing_desc_exit" not in excluded_tests
            and "all" in chosen_tests
            or "missing_desc_exit" in chosen_tests
        ):
            missing_desc_exit_result = (
                check_missing_desc_exit.has_missing_desc_exit(file)
            )

        if (
            "misuse_forking_funcs" not in excluded_tests
            and "all" in chosen_tests
            or "misuse_forking_funcs" in chosen_tests
        ):
            misuse_forking_funcs_result = (
                check_forking_nasl_funcs.is_misusing_forking_funcs(file)
            )

        if (
            "valid_script_tag_names" not in excluded_tests
            and "all" in chosen_tests
            or "valid_script_tag_names" in chosen_tests
        ):
            valid_script_tag_names_result = (
                check_valid_script_tag_names.has_valid_script_tag_names(file)
            )

        if (
            "empty_values" not in excluded_tests
            and "all" in chosen_tests
            or "empty_values" in chosen_tests
        ):
            empty_value_result = check_script_calls_and_tags.has_empty_values(
                file
            )

        if (
            "log_message_with_severity" not in excluded_tests
            and "all" in chosen_tests
            or "log_message_with_severity" in chosen_tests
        ):
            using_log_message_with_severity_result = (
                check_log_messages.is_using_log_message_with_severity(file)
            )

        if (
            "security_message_without_severity" not in excluded_tests
            and "all" in chosen_tests
            or "security_message_without_severity" in chosen_tests
        ):
            using_security_message_without_severity_result = (
                check_security_messages.run(file)
            )

        if (
            "valid_script_add_preference_type" not in excluded_tests
            and "all" in chosen_tests
            or "valid_script_add_preference_type" in chosen_tests
        ):
            valid_script_add_preference_type_result = check_script_add_preference_type.has_valid_script_add_preference_type(
                file
            )

        if (
            "dependency_category_order" not in excluded_tests
            and "all" in chosen_tests
            or "dependency_category_order" in chosen_tests
        ):
            dependency_category_order_result = (
                check_dependency_category_order.run(file)
            )

        if (
            "valid_oid" not in excluded_tests
            and "all" in chosen_tests
            or "valid_oid" in chosen_tests
        ):
            valid_oid_result = check_valid_oid.has_valid_oid(file)

        if (
            "deprecated_dependency" not in excluded_tests
            and "all" in chosen_tests
            or "deprecated_dependency" in chosen_tests
        ):
            deprecated_dependency_result = (
                check_deprecated_dependency.has_deprecated_dependency(file)
            )

        if (
            "missing_solution_tag" not in excluded_tests
            and "all" in chosen_tests
            or "missing_solution_tag" in chosen_tests
        ):
            missing_solution_tag_result = (
                check_missing_solution_tag.has_missing_solution_tag(file)
            )

        # On full runs it is expected that scripts are not changed/modified and this would report a false positive
        # The same is currently also valid when a commit range is passed on command line.
        if not FULL and not use_commit_range:
            if (
                "check_updated_date_version" not in excluded_tests
                and "all" in chosen_tests
                or "check_updated_date_version" in chosen_tests
            ):
                check_updated_date_version_result = (
                    check_updated_date_version.run(file)
                )

        if (
            "check_vt_placement" not in excluded_tests
            and "all" in chosen_tests
            or "check_vt_placement" in chosen_tests
        ):
            check_vt_placement_result = check_vt_placement.run(file)

        if (
            "get_kb_on_services" not in excluded_tests
            and "all" in chosen_tests
            or "get_kb_on_services" in chosen_tests
        ):
            get_kb_on_services_result = check_get_kb_on_services.run(file)

        # On full runs we're not getting a diff between two commits so skipping these here.
        if not FULL:
            if (
                "changed_oid" not in excluded_tests
                and "all" in chosen_tests
                or "changed_oid" in chosen_tests
            ):
                if use_commit_range:
                    changed_oid_result = check_changed_oid.run(
                        file, passed_commit_range
                    )
                else:
                    changed_oid_result = check_changed_oid.run(file, "HEAD")

        if (
            "prod_svc_detect_in_vulnvt" not in excluded_tests
            and "all" in chosen_tests
            or "prod_svc_detect_in_vulnvt" in chosen_tests
        ):
            prod_svc_detect_in_vulnvt_result = (
                check_prod_svc_detect_in_vulnvt.run(file)
            )

        if (
            "doubled_end_point" not in excluded_tests
            and "all" in chosen_tests
            or "doubled_end_point" in chosen_tests
        ):
            doubled_end_point_result = check_doubled_end_point.run(file)

    if (
        "encoding" not in excluded_tests
        and "all" in chosen_tests
        or "encoding" in chosen_tests
    ):
        encoding_result = check_encoding.check_encoding(file)

    if (
        "deprecated_functions" not in excluded_tests
        and "all" in chosen_tests
        or "deprecated_functions" in chosen_tests
    ):
        deprecated_functions_result = (
            check_deprecated_functions.is_using_only_current_functions(file)
        )

    if not FULL:
        if (
            "lint" not in excluded_tests
            and "all" in chosen_tests
            or "lint" in chosen_tests
        ):
            lint_result = check_lint.is_lint_correct(
                file, vtdir, None, None, False
            )

    if (
        "display" not in excluded_tests
        and "all" in chosen_tests
        or "display" in chosen_tests
    ):
        display_result = check_display.is_using_display(file)
        display_result_debug = check_display.is_using_display_if_commented(file)

    if (
        "badwords" not in excluded_tests
        and "all" in chosen_tests
        or "badwords" in chosen_tests
    ):
        badwords_result = check_badwords.has_badword(file)

    # If a "full" run is requested, codespell will run against the whole folder once down below.
    # Another case is the --non-recursive flag where codespell would run against a whole
    # directory but we want to just report spelling mistakes in a non-recursive way.
    if (FULL and not recursive) or not FULL:
        if (
            "codespell" not in excluded_tests
            and "all" in chosen_tests
            or "codespell" in chosen_tests
        ):
            codespell_result = check_spelling.has_spelling_errors(
                file, cwd, vtdir, False, include_regex, exclude_regex
            )

    if (
        "newline" not in excluded_tests
        and "all" in chosen_tests
        or "newlines" in chosen_tests
    ):
        newlines_result = check_newlines.has_wrong_newlines(file)

    if DEBUG:
        if (
            "tbd_todo" not in excluded_tests
            and "all" in chosen_tests
            or "tbd_todo" in chosen_tests
        ):
            tbd_todo_result = check_todo_tbd.run(file)
            if tbd_todo_result[0] == 1:
                debug_messages += tbd_todo_result[1] + "\r\n"

    if (
        "set_get_kb_calls" not in excluded_tests
        and "all" in chosen_tests
        or "set_get_kb_calls" in chosen_tests
    ):
        set_get_kb_calls_result = (
            check_set_get_kb_calls.has_wrong_set_get_kb_call(file)
        )

    if (
        "var_assign_in_if" not in excluded_tests
        and "all" in chosen_tests
        or "var_assign_in_if" in chosen_tests
    ):
        var_assign_in_if_result = check_var_assign_in_if.has_var_assign_in_if(
            file
        )

    if (
        "misplaced_compare_in_if" not in excluded_tests
        and "all" in chosen_tests
        or "misplaced_compare_in_if" in chosen_tests
    ):
        misplaced_compare_in_if_result = (
            check_misplaced_compare_in_if.has_misplaced_compare_in_if(file)
        )

    if (
        "check_for_tabs" not in excluded_tests
        and "all" in chosen_tests
        or "check_for_tabs" in chosen_tests
    ):
        check_for_tabs_result = check_for_tabs.is_using_tabs(file)

    if (
        "trailing_spaces_tabs" not in excluded_tests
        and "all" in chosen_tests
        or "trailing_spaces_tabs" in chosen_tests
    ):
        trailing_spaces_tabs_result = (
            check_trailing_spaces_tabs.has_trailing_spaces_tabs(file)
        )

    if (
        "grammar" not in excluded_tests
        and "all" in chosen_tests
        or "grammar" in chosen_tests
    ):
        grammar_result = check_grammar.run(file)

    if encoding_result[0] == -1:
        encoding_error = True
        encoding_error_text += encoding_result[1] + "\r\n"
    elif encoding_result[0] == 1:
        debug_messages += encoding_result[1] + "\r\n"

    if cve_format_result[0] == -1:
        cve_format_error = True
        cve_format_error_text += cve_format_result[1] + "\r\n"
    elif cve_format_result[0] == 1:
        debug_messages += cve_format_result[1] + "\r\n"

    if cvss_format_result[0] == -1:
        cvss_format_error = True
        cvss_format_error_text += cvss_format_result[1] + "\r\n"

    if creation_date_result[0] == -1:
        creation_date_error = True
        creation_date_error_text += creation_date_result[1] + "\r\n"

    if lint_result[0] == -1:
        lint_error = True
        lint_error_text += lint_result[1] + "\r\n"
    elif lint_result[0] == 1:
        debug_messages += lint_result[1] + "\r\n"

    if display_result[0] == -1:
        display_error = True
        display_error_text += display_result[1] + "\r\n"

    if display_result_debug[0] == 1:
        debug_messages += display_result_debug[1] + "\r\n"

    if mandatory_script_calls_result[0] == -1:
        mandatory_script_calls_error = True
        mandatory_script_calls_error_text += (
            mandatory_script_calls_result[1] + "\r\n"
        )

    if recommended_script_calls_result[0] == 1:
        debug_messages += recommended_script_calls_result[1] + "\r\n"

    if mandatory_script_tags_result[0] == -1:
        mandatory_script_tags_error = True
        mandatory_script_tags_error_text += (
            mandatory_script_tags_result[1] + "\r\n"
        )

    if solution_type_result[0] == -1:
        solution_type_error = True
        solution_type_error_text += solution_type_result[1] + "\r\n"
    elif solution_type_result[0] == 1:
        debug_messages += solution_type_result[1] + "\r\n"

    if family_result[0] == -1:
        family_error = True
        family_error_text += family_result[1] + "\r\n"

    if qod_result[0] == -1:
        qod_error = True
        qod_error_text += qod_result[1] + "\r\n"

    if codespell_result[0] == -1:
        codespell_error = True
        codespell_error_text += codespell_result[1] + "\r\n"
    elif codespell_result[0] == 1:
        debug_messages += codespell_result[1] + "\r\n"

    if dependencies_result[0] == -1:
        dependencies_error = True
        dependencies_error_text += dependencies_result[1] + "\r\n"
    elif dependencies_result[0] == 1:
        debug_messages += dependencies_result[1] + "\r\n"

    if valid_script_tag_result[0] == -1:
        valid_script_tag_error = True
        valid_script_tag_error_text += valid_script_tag_result[1] + "\r\n"

    if duplicate_oid_result[0] == -1:
        duplicate_oid_error = True
        duplicate_oid_error_text += duplicate_oid_result[1] + "\r\n"
    elif duplicate_oid_result[0] == 1:
        debug_messages += duplicate_oid_result[1] + "\r\n"

    if illegal_characters_result[0] == -1:
        illegal_characters_error = True
        illegal_characters_error_text += illegal_characters_result[1] + "\r\n"

    if deprecated_functions_result[0] == -1:
        deprecated_functions_error = True
        deprecated_functions_error_text += (
            deprecated_functions_result[1] + "\r\n"
        )

    if solution_text_result[0] == -1:
        solution_text_error = True
        solution_text_error_text += solution_text_result[1] + "\r\n"

    if newlines_result[0] == -1:
        newlines_error = True
        newlines_error_text += newlines_result[1] + "\r\n"

    if copyright_year_result[0] == -1:
        copyright_year_error = True
        copyright_year_error_text += copyright_year_result[1] + "\r\n"
    elif copyright_year_result[0] == 1:
        debug_messages += copyright_year_result[1] + "\r\n"

    if copyright_text_result[0] == -1:
        copyright_text_error = True
        copyright_text_error_text += copyright_text_result[1] + "\r\n"

    if scm_tags_result[0] == -1:
        scm_tags_error = True
        scm_tags_error_text += scm_tags_result[1] + "\r\n"

    if script_tag_newlines_result[0] == -1:
        script_tag_newlines_error = True
        script_tag_newlines_error_text += script_tag_newlines_result[1] + "\r\n"

    if badwords_result[0] == -1:
        badwords_error = True
        badwords_error_text += badwords_result[1] + "\r\n"

    if overlong_script_tags_result[0] == -1:
        overlong_script_tags_error = True
        overlong_script_tags_error_text += (
            overlong_script_tags_result[1] + "\r\n"
        )

    if http_link_in_tag_result[0] == -1:
        http_link_in_tag_error = True
        http_link_in_tag_error_text += http_link_in_tag_result[1] + "\r\n"

    if nvd_mitre_link_in_xref_result[0] == -1:
        nvd_mitre_link_in_xref_error = True
        nvd_mitre_link_in_xref_error_text += (
            nvd_mitre_link_in_xref_result[1] + "\r\n"
        )

    if trail_lead_nts_in_tag_result[0] == -1:
        trail_lead_nts_in_tag_error = True
        trail_lead_nts_in_tag_error_text += (
            trail_lead_nts_in_tag_result[1] + "\r\n"
        )

    if valid_url_script_xref_result[0] == -1:
        valid_url_script_xref_error = True
        valid_url_script_xref_error_text += (
            valid_url_script_xref_result[1] + "\r\n"
        )

    if category_result[0] == -1:
        category_error = True
        category_error_text += category_result[1] + "\r\n"

    if duplicate_script_tags_result[0] == -1:
        duplicate_script_tags_error = True
        duplicate_script_tags_error_text += (
            duplicate_script_tags_result[1] + "\r\n"
        )

    if missing_desc_exit_result[0] == -1:
        missing_desc_exit_error = True
        missing_desc_exit_error_text += missing_desc_exit_result[1] + "\r\n"
    elif missing_desc_exit_result[0] == 1:
        debug_messages += missing_desc_exit_result[1] + "\r\n"

    if misuse_forking_funcs_result[0] == -1:
        misuse_forking_funcs_error = True
        misuse_forking_funcs_error_text += (
            misuse_forking_funcs_result[1] + "\r\n"
        )

    if set_get_kb_calls_result[0] == -1:
        set_get_kb_calls_error = True
        set_get_kb_calls_error_text += set_get_kb_calls_result[1] + "\r\n"

    if empty_value_result[0] == -1:
        empty_value_error = True
        empty_value_error_text += empty_value_result[1] + "\r\n"

    if valid_script_tag_names_result[0] == -1:
        valid_script_tag_names_error = True
        valid_script_tag_names_error_text += (
            valid_script_tag_names_result[1] + "\r\n"
        )

    if using_log_message_with_severity_result[0] == -1:
        using_log_message_with_severity_error = True
        using_log_message_with_severity_error_text += (
            using_log_message_with_severity_result[1] + "\r\n"
        )
    elif using_log_message_with_severity_result[0] == 1:
        debug_messages += using_log_message_with_severity_result[1] + "\r\n"

    if using_security_message_without_severity_result[0] == -1:
        using_security_message_without_severity_error = True
        using_security_message_without_severity_error_text += (
            using_security_message_without_severity_result[1] + "\r\n"
        )

    if valid_script_add_preference_type_result[0] == -1:
        valid_script_add_preference_type_error = True
        valid_script_add_preference_type_error_text += (
            valid_script_add_preference_type_result[1] + "\r\n"
        )

    if var_assign_in_if_result[0] == -1:
        var_assign_in_if_error = True
        var_assign_in_if_error_text += var_assign_in_if_result[1] + "\r\n"

    if dependency_category_order_result[0] == -1:
        dependency_category_order_error = True
        dependency_category_order_error_text += (
            dependency_category_order_result[1] + "\r\n"
        )
    elif dependency_category_order_result[0] == 1:
        debug_messages += dependency_category_order_result[1] + "\r\n"

    if valid_oid_result[0] == -1:
        valid_oid_error = True
        valid_oid_error_text += valid_oid_result[1] + "\r\n"

    if misplaced_compare_in_if_result[0] == -1:
        misplaced_compare_in_if_error = True
        misplaced_compare_in_if_error_text += (
            misplaced_compare_in_if_result[1] + "\r\n"
        )

    if deprecated_dependency_result[0] == -1:
        deprecated_dependency_error = True
        deprecated_dependency_error_text += (
            deprecated_dependency_result[1] + "\r\n"
        )
    elif deprecated_dependency_result[0] == 1:
        debug_messages += deprecated_dependency_result[1] + "\r\n"

    if missing_solution_tag_result[0] == -1:
        missing_solution_tag_error = True
        missing_solution_tag_error_text += (
            missing_solution_tag_result[1] + "\r\n"
        )

    if check_for_tabs_result[0] == -1:
        check_for_tabs_error = True
        check_for_tabs_error_text += check_for_tabs_result[1] + "\r\n"

    if trailing_spaces_tabs_result[0] == -1:
        trailing_spaces_tabs_error = True
        trailing_spaces_tabs_error_text += (
            trailing_spaces_tabs_result[1] + "\r\n"
        )

    if check_updated_date_version_result[0] == -1:
        check_updated_date_version_error = True
        check_updated_date_version_error_text += (
            check_updated_date_version_result[1] + "\r\n"
        )

    if check_vt_placement_result[0] == -1:
        check_vt_placement_error = True
        check_vt_placement_error_text += check_vt_placement_result[1] + "\r\n"

    if get_kb_on_services_result[0] == -1:
        get_kb_on_services_error = True
        get_kb_on_services_error_text += get_kb_on_services_result[1] + "\r\n"

    if changed_oid_result[0] == -1:
        changed_oid_warning = True
        changed_oid_warning_text += changed_oid_result[1] + "\r\n"

    if prod_svc_detect_in_vulnvt_result[0] == -1:
        prod_svc_detect_in_vulnvt_error = True
        prod_svc_detect_in_vulnvt_error_text += (
            prod_svc_detect_in_vulnvt_result[1] + "\r\n"
        )

    if grammar_result[0] == -1:
        grammar_error = True
        grammar_error_text += grammar_result[1] + "\r\n"

    if doubled_end_point_result[0] == -1:
        doubled_end_point_error = True
        doubled_end_point_error_text += doubled_end_point_result[1] + "\r\n"

if FULL and recursive:
    if (
        "codespell" not in excluded_tests
        and "all" in chosen_tests
        or "codespell" in chosen_tests
    ):
        start_dir = start_dir.replace("./", "/")
        if start_dir[:1] != "/":
            start_dir = "/" + start_dir
        codespell_result = check_spelling.has_spelling_errors(
            file, cwd, vtdir + start_dir, True, include_regex, exclude_regex
        )
        if codespell_result[0] == -1:
            codespell_error = True
            codespell_error_text += codespell_result[1] + "\r\n"
        elif codespell_result[0] == 1:
            debug_messages += codespell_result[1] + "\r\n"

if FULL:
    if (
        "lint" not in excluded_tests
        and "all" in chosen_tests
        or "lint" in chosen_tests
    ):
        lint_result = check_lint.is_lint_correct(
            None, vtdir, dir_list, inc_list, True
        )
        if lint_result[0] == -1:
            lint_error = True
            lint_error_text += lint_result[1] + "\r\n"

if DEBUG and debug_messages != "":
    print("======= BEGIN DEBUG MESSAGES =======\r\n\r\n")
    print(debug_messages)
    print("======= END DEBUG MESSAGES =======\r\n\r\n")
    print("\r\n\r\n\r\n")

printed_error_header = False
printed_warning_header = False

if encoding_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Encoding -----\r\n")
    print(encoding_error_text)
    test_success = False

if cve_format_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- CVE Format -----\r\n")
    print(cve_format_error_text)
    test_success = False

if cvss_format_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- CVSS Format -----\r\n")
    print(cvss_format_error_text)
    test_success = False

if creation_date_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Creation Date -----\r\n")
    print(creation_date_error_text)
    test_success = False

if lint_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- OpenVAS NASL Lint -----\r\n")
    print(lint_error_text)
    test_success = False

if display_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- display() Function -----\r\n")
    print(display_error_text)
    test_success = False

if mandatory_script_calls_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script calls -----\r\n")
    print(mandatory_script_calls_error_text)
    test_success = False

if mandatory_script_tags_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script tags -----\r\n")
    print(mandatory_script_tags_error_text)
    test_success = False

if solution_type_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- solution_type -----\r\n")
    print(solution_type_error_text)
    test_success = False

if family_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script_family -----\r\n")
    print(family_error_text)
    test_success = False

if qod_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- QoD -----\r\n")
    print(qod_error_text)
    test_success = False

if codespell_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Spelling -----\r\n")
    print(codespell_error_text)
    test_success = False

if dependencies_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script_dependencies -----\r\n")
    print(dependencies_error_text)
    test_success = False

if valid_script_tag_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script_tag / script_xref -----\r\n")
    print(valid_script_tag_error_text)
    test_success = False

if duplicate_oid_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- duplicate OIDs -----\r\n")
    print(duplicate_oid_error_text)
    test_success = False

if illegal_characters_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Illegal Characters -----\r\n")
    print(illegal_characters_error_text)
    test_success = False

if deprecated_functions_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Deprecated Functions -----\r\n")
    print(deprecated_functions_error_text)
    test_success = False

if solution_text_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong solution text -----\r\n")
    print(solution_text_error_text)
    test_success = False

if newlines_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong newlines -----\r\n")
    print(newlines_error_text)
    test_success = False

if copyright_year_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong Copyright year -----\r\n")
    print(copyright_year_error_text)
    test_success = False

if copyright_text_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong Copyright text -----\r\n")
    print(copyright_text_error_text)
    test_success = False

if scm_tags_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong SCM tag syntax -----\r\n")
    print(scm_tags_error_text)
    test_success = False

if script_tag_newlines_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Unallowed newline in script_tag -----\r\n")
    print(script_tag_newlines_error_text)
    test_success = False

if badwords_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using an unallowed word -----\r\n")
    print(badwords_error_text)
    test_success = False

if overlong_script_tags_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using overlong script_tags -----\r\n")
    print(overlong_script_tags_error_text)
    test_success = False

if http_link_in_tag_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using an HTTP Link/URL within a tag -----\r\n")
    print(http_link_in_tag_error_text)
    test_success = False

if nvd_mitre_link_in_xref_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using an link to Mitre/NVD within the script_xref -----\r\n")
    print(nvd_mitre_link_in_xref_error_text)
    test_success = False

if trail_lead_nts_in_tag_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- Using a leading and/or trailing newline, tab or space within the script_tag -----\r\n"
    )
    print(trail_lead_nts_in_tag_error_text)
    test_success = False

if valid_url_script_xref_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- URL in script_xref doesn't start with a http://, https://, ftp:// or ftps:// or using a newline, tab or space -----\r\n"
    )
    print(valid_url_script_xref_error_text)
    test_success = False

if category_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- script_category -----\r\n")
    print(category_error_text)
    test_success = False

if duplicate_script_tags_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Duplicated script tags -----\r\n")
    print(duplicate_script_tags_error_text)
    test_success = False

if missing_desc_exit_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Missing exit(0); in description block -----\r\n")
    print(missing_desc_exit_error_text)
    test_success = False

if misuse_forking_funcs_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Misusing forking functions -----\r\n")
    print(misuse_forking_funcs_error_text)
    test_success = False

if set_get_kb_calls_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Wrong set/get KB calls -----\r\n")
    print(set_get_kb_calls_error_text)
    test_success = False

if empty_value_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- empty value -----\r\n")
    print(empty_value_error_text)
    test_success = False

if valid_script_tag_names_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- valid script_tag names -----\r\n")
    print(valid_script_tag_names_error_text)
    test_success = False

if using_log_message_with_severity_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using a log_message in a VT with a severity -----\r\n")
    print(using_log_message_with_severity_error_text)
    test_success = False

if using_security_message_without_severity_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using a security_message in a VT without a severity -----\r\n")
    print(using_security_message_without_severity_error_text)
    test_success = False

if valid_script_add_preference_type_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- valid script_add_preference types -----\r\n")
    print(valid_script_add_preference_type_error_text)
    test_success = False

if var_assign_in_if_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using a variable assignment within an if call -----\r\n")
    print(var_assign_in_if_error_text)
    test_success = False

if dependency_category_order_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- VTs with out-of-order / not allowed dependencies -----\r\n")
    print(dependency_category_order_error_text)
    test_success = False

if valid_oid_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- valid script_oid -----\r\n")
    print(valid_oid_error_text)
    test_success = False

if misplaced_compare_in_if_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- misplaced compare within an if() call -----\r\n")
    print(misplaced_compare_in_if_error_text)
    test_success = False

if deprecated_dependency_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Dependency to deprecated VT -----\r\n")
    print(deprecated_dependency_error_text)
    test_success = False

if missing_solution_tag_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Missing solution_tag -----\r\n")
    print(missing_solution_tag_error_text)
    test_success = False

if check_for_tabs_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using tabs instead of spaces -----\r\n")
    print(check_for_tabs_error_text)
    test_success = False

if trailing_spaces_tabs_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- Using trailing spaces and/or tabs -----\r\n")
    print(trailing_spaces_tabs_error_text)
    test_success = False

if check_updated_date_version_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- Unchanged script_version or last_modification tag(s) -----\r\n"
    )
    print(check_updated_date_version_error_text)
    test_success = False

if check_vt_placement_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- VTs which should be placed in the root directory -----\r\n")
    print(check_vt_placement_error_text)
    test_success = False

if get_kb_on_services_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- VTs which are accessing a 'Services/' KB key directly -----\r\n"
    )
    print(get_kb_on_services_error_text)
    test_success = False

if prod_svc_detect_in_vulnvt_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- Vulnerability-VTs which are doing a product / service detection -----\r\n"
    )
    print(prod_svc_detect_in_vulnvt_error_text)
    test_success = False

if grammar_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print("----- VTs/Includes which have grammar problems -----\r\n")
    print(grammar_error_text)
    test_success = False

if doubled_end_point_error:
    if not printed_error_header:
        printed_error_header = True
        print("========== BEGIN ERRORS ==========\r\n\r\n")

    print(
        "----- VTs having a script_tag ending with more then one end point -----\r\n"
    )
    print(doubled_end_point_error_text)
    test_success = False

if printed_error_header:
    print("\r\n========== END ERRORS ==========")

# nb: Keep the WARNINGs at the bottom
if changed_oid_warning:
    if not printed_warning_header:
        printed_warning_header = True
        print("\r\n========== BEGIN WARNINGS ==========\r\n")

    print("----- Changed OID -----\r\n")
    print(changed_oid_warning_text)

if printed_warning_header:
    print("\r\n========== END WARNINGS ==========")

if not printed_warning_header:
    print("\r\n- No Warnings found")

if not printed_error_header:
    print("\r\n- No Errors found")

# Change back to the current working directory
os.chdir(cwd)

if not test_success:
    exit(-1)
