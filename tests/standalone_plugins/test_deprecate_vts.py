# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
# pylint: disable=line-too-long
# pylint: disable=protected-access
import unittest
from pathlib import Path
from tests.plugins import TemporaryDirectory

from troubadix.standalone_plugins.deprecate_vts import (
    deprecate,
    parse_args,
    DeprecatedFile,
    _get_summary,
    _finalize_content,
    update_summary,
    get_files_from_path,
    filter_files,
)


class ParseArgsTestCase(unittest.TestCase):
    def test_parse_args(self):
        testfile = "testfile.nasl"
        output_path = "attic/"
        reason = "NOTUS"

        args = parse_args(
            [
                "--files",
                testfile,
                "--output-path",
                output_path,
                "--deprecation-reason",
                reason,
            ]
        )
        self.assertEqual(args.files, [Path(testfile)])
        self.assertEqual(args.output_path, Path(output_path))
        self.assertEqual(args.deprecation_reason, reason)

    def test_mandatory_arg_group_both(self):
        testfile = "testfile.nasl"
        output_path = "attic/"
        input_path = "nasl/common"
        reason = "NOTUS"

        with self.assertRaises(SystemExit):
            parse_args(
                [
                    "--files",
                    testfile,
                    "--output-path",
                    output_path,
                    "--input-path",
                    input_path,
                    "--deprecation-reason",
                    reason,
                ]
            )

    def test_invalid_reason(self):
        output_path = "attic/"
        input_path = "nasl/common"
        reason = "foo"
        with self.assertRaises(SystemExit):
            parse_args(
                [
                    "--output-path",
                    output_path,
                    "--input-path",
                    input_path,
                    "--deprecation-reason",
                    reason,
                ]
            )

    def test_mandatory_arg_group_neither(self):
        output_path = "attic/"
        reason = "NOTUS"
        with self.assertRaises(SystemExit):
            parse_args(
                [
                    "--output-path",
                    output_path,
                    "--deprecation-reason",
                    reason,
                ]
            )


NASL_CONTENT = (
    '...if(description)\n{\n  script_oid("1.3.6.1.4.1.25623.1.0.910673");'
    '\n  script_version("2024-03-12T14:15:13+0000");'
    '\n  script_name("RedHat: Security Advisory for gd (RHSA-2020:5443-01)");'
    '\n  script_family("Red Hat Local Security Checks");\n  script_dependencies("gather-package-list.nasl");'
    '\n  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");'
    '\n\n  script_xref(name:"RHSA", value:"2020:5443-01");\n  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2020-December/msg00044.html");'
    '\n\n  script_tag(name:"summary", value:"The remote host is missing an update for the \'gd\'\n  package(s) announced via the RHSA-2020:5443-01 advisory.");'
    '\n\n  exit(0);\n}\n\ninclude("revisions-lib.inc");\ninclude("pkg-lib-rpm.inc");\n\nrelease = rpm_get_ssh_release();\nif(!release)\n  exit(0);\n\nres = "";\nreport = "";\n\nif(release == "RHENT_7") {\n\n  if(!isnull(res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.35~27.el7_9", rls:"RHENT_7"))) {\n    report += res;\n  }\n\n  if(!isnull(res = isrpmvuln(pkg:"gd-debuginfo", rpm:"gd-debuginfo~2.0.35~27.el7_9", rls:"RHENT_7"))) {\n    report += res;\n  }\n\n  if(report != "") {\n    security_message(data:report);\n  } else if(__pkg_match) {\n    exit(99);\n  }\n  exit(0);\n}\n\nexit(0);'
)

NASL_CONTENT_KB = (
    '...if(description)\n{\n  script_oid("1.3.6.1.4.1.25623.1.0.910673");'
    '\n  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");'
    '\n\n  set_kb_item(name:"shttp/" + port + "/detected", value:TRUE);"'
    '\n\n  script_tag(name:"summary", value:"The remote host is missing an update for the \'gd\'\n  package(s) announced via the RHSA-2020:5443-01 advisory.");'
    '\n\n  exit(0);\n}\n\ninclude("revisions-lib.inc");\ninclude("pkg-lib-rpm.inc");\n\nrelease = rpm_get_ssh_release();\nif(!release)\n  exit(0);\n\nres = "";\nreport = "";\n\nif(release == "RHENT_7") {\n\n  if(!isnull(res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.35~27.el7_9", rls:"RHENT_7"))) {\n    report += res;\n  }\n\n  if(!isnull(res = isrpmvuln(pkg:"gd-debuginfo", rpm:"gd-debuginfo~2.0.35~27.el7_9", rls:"RHENT_7"))) {\n    report += res;\n  }\n\n  if(report != "") {\n    security_message(data:report);\n  } else if(__pkg_match) {\n    exit(99);\n  }\n  exit(0);\n}\n\nexit(0);'
)


class DeprecateVTsTestCase(unittest.TestCase):
    def test_deprecate(self):
        with TemporaryDirectory() as out_dir, TemporaryDirectory() as in_dir:
            testfile1 = in_dir / "testfile1.nasl"
            testfile1.write_text(NASL_CONTENT, encoding="utf8")

            testfile2 = out_dir / "testfile1.nasl"
            testfile2.touch()

            to_deprecate = [
                DeprecatedFile(
                    name="testfile1.nasl",
                    full_path=testfile1,
                    content=NASL_CONTENT,
                )
            ]
            deprecate(out_dir, to_deprecate, "NOTUS")

            result = testfile2.read_text(encoding="utf8")
            self.assertNotIn(result, "script_mandatory_keys")
            self.assertNotIn(result, "script_dependencies")
            self.assertNotIn(result, 'include("revisions-lib.inc");')
            assert (
                "Note: This VT has been deprecated and replaced by "
                "a Notus scanner based one."
            ) in result

    def test_deprecate_kb_item(self):
        with TemporaryDirectory() as out_dir, TemporaryDirectory() as in_dir:
            testfile1 = in_dir / "testfile1.nasl"
            testfile1.write_text(NASL_CONTENT_KB, encoding="utf8")

            to_deprecate = [
                DeprecatedFile(
                    name="testfile1.nasl",
                    full_path=testfile1,
                    content=NASL_CONTENT_KB,
                )
            ]
            deprecate(out_dir, to_deprecate, "NOTUS")
            self.assertLogs(
                "Unable to deprecate testfile1.nasl. There are still KB keys "
                "remaining."
            )

    def test_get_summary(self):
        result = _get_summary(NASL_CONTENT)
        expected = (
            "The remote host is missing an update for the 'gd'\n  package(s) "
            "announced "
            "via the RHSA-2020:5443-01 advisory."
        )
        self.assertEqual(result, expected)

    def test_finalize_content(self):

        result = _finalize_content(NASL_CONTENT)
        expected = (
            '...if(description)\n{\n  script_oid("1.3.6.1.4.1.25623.1.0.910673");\n  '
            'script_version("2024-03-12T14:15:13+0000");\n  script_name("RedHat: Security Advisory for gd (RHSA-2020:5443-01)");\n  script_family("Red Hat Local Security Checks");\n  script_dependencies("gather-package-list.nasl");\n  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");\n\n  script_xref(name:"RHSA", value:"2020:5443-01");\n  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2020-December/msg00044.html");\n\n  script_tag(name:"summary", value:"The remote host is missing an update for the \'gd\'\n  package(s) announced via the RHSA-2020:5443-01 advisory.");\n\n  script_tag(name:"deprecated", value:TRUE);\n\nexit(0);\n}\n\nexit(66);\n'
        )
        self.assertEqual(result, expected)

    def test_update_summary_no_oid_match(self):
        file = DeprecatedFile(
            name="testfile.nasl",
            full_path=Path("dir/testfile.nasl"),
            content=NASL_CONTENT,
        )
        result = update_summary(file, "NOTUS")
        self.assertIn("This VT has been deprecated", result)

    def test_get_files_from_path(self):
        with TemporaryDirectory() as in_dir:
            testfile1 = in_dir / "gb_rhsa_2021_8383_8383.nasl"
            testfile1.write_text(NASL_CONTENT, encoding="utf8")

            result = get_files_from_path(dir_path=in_dir)
            expected = [testfile1]

            self.assertEqual(result, expected)

    def test_filter_files(self):
        with TemporaryDirectory() as in_dir:
            testfile1 = in_dir / "gb_rhsa_2021_8383_8383.nasl"
            testfile1.write_text(NASL_CONTENT, encoding="utf8")
            testfile2 = in_dir / "gb_rhsa_2020_8383_8383.nasl"
            testfile2.write_text(NASL_CONTENT, encoding="utf8")

            result = filter_files(
                files=[testfile1, testfile2], filename_prefix="gb_rhsa_2021"
            )
            expected = [
                DeprecatedFile(
                    name="gb_rhsa_2021_8383_8383.nasl",
                    full_path=in_dir / "gb_rhsa_2021_8383_8383.nasl",
                    content=NASL_CONTENT,
                )
            ]

            self.assertEqual(result, expected)

    def test_filter_files_out(self):
        with TemporaryDirectory() as in_dir:
            testfile1 = in_dir / "gb_rhsa_2021_8383_8383.nasl"
            testfile1.write_text(NASL_CONTENT, encoding="utf8")

            result = filter_files(
                files=[testfile1], filename_prefix="gb_rhsa_2020"
            )
            expected = []

            self.assertEqual(result, expected)
