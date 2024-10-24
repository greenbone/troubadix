# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path

from tests.plugins import PluginTestCase
from troubadix.plugin import LinterError
from troubadix.plugins.script_xref_url import CheckScriptXrefUrl


class CheckScriptXrefUrlTestCase(PluginTestCase):
    path = Path("some/file.nasl")

    def test_ok(self):
        content = (
            '  script_xref(name:"URL", value:"http://www.example.com");\n'
            # pylint: disable=line-too-long
            # Various cases from https://github.com/python-validators/validators/issues/296
            '  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2718993");\n'
            '  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10983-fg-vd-19-086-livezilla-server-is-vulnerable-to-sql-injection-ii/");\n'
            '  script_xref(name:"URL", value:"http://www.brocade.com/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-168.pdf");\n'
            '  script_xref(name:"URL", value:"https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/8SA-M3as7A8");\n'
            '  script_xref(name:"URL", value:"https://forum.bitdefender.com/index.php?/topic/75470-doubleagent/");\n'
            '  script_xref(name:"URL", value:"https://www.smartftp.com/forums/index.php?/topic/16425-smartftp-client-40-change-log/");\n'
            '  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/#/vulnerabilities/100912");\n'
            '  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer");\n'
            '  script_xref(name:"URL", value:"https://www.watchguard.com/support/release-notes/fireware/12/en-US/EN_ReleaseNotes_Fireware_12_5_9/index.html#Fireware/en-US/resolved_issues.html");\n'
            '  script_xref(name:"URL", value:"https://code.wireshark.org/review/#/c/25660/");\n'
            '  script_xref(name:"URL", value:"https://groups.google.com/forum/#!topic/kubernetes-announce/yBrFf5nmvfI");\n'
            '  script_xref(name:"URL", value:"https://issues.sonatype.org/plugins/servlet/mobile#issue/NEXUS-16870");\n'
            '  script_xref(name:"URL", value:"http://forums.livezilla.net/index.php?/topic/163-livezilla-changelog/");\n'
            '  script_xref(name:"URL", value:"https://www.watchguard.com/support/release-notes/fireware/11/en-US/EN_ReleaseNotes_Fireware_11_12_1/index.html#Fireware/en-US/resolved_issues.html%3FTocPath%3D_____13");\n'
            '  script_xref(name:"URL", value:"https://review.typo3.org/#/c/37013");\n'
            '  script_xref(name:"URL", value:"https://forums.malwarebytes.org/index.php?/topic/158251-malwarebytes-anti-exploit-hall-of-fame/");\n'
            '  script_xref(name:"URL", value:"http://speedtouch.sourceforge.io/index.php?/news.en.html");\n'
            '  script_xref(name:"URL", value:"https://support.k7computing.com/index.php?/Knowledgebase/Article/View/173/41/advisory-issued-on-6th-november-2017");\n'
            '  script_xref(name:"URL", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?/10077872.htm");\n'
            '  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/54-Update-on-MatrixSSL-miscalculation-CVE-2016-8671,-incomplete-fix-for-CVE-2016-6887.html");\n'
            '  script_xref(name:"URL", value:"http://www.scaprepo.com/view.jsp?id=oval:org.secpod.oval:def:701638");\n'
            '  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/46-Various-invalid-memory-reads-in-ImageMagick-WPG,-DDS,-DCM.html");\n'
            '  script_xref(name:"URL", value:"http://forum.wampserver.com/read.php?2,153491");\n'
            '  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:04.jail.asc");\n'
            '  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-004-turboftp-server-1-00-712-dos/");\n'
            '  script_xref(name:"URL", value:"http://core.yehg.net/lab/pr0js/advisories/dll_hijacking/[flash_player]_10.1.x_insecure_dll_hijacking_(dwmapi.dll)");\n'
            '  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/perl-advocacy/200904.mbox/<ad28918e0904011458h273a71d4x408f1ed286c9dfbc@mail.gmail.com>");\n'
            '  script_xref(name:"URL", value:"https://confluence.atlassian.com/security/security-bulletin-may-21-2024-1387867145.html");\n'
            # pylint: enable=line-too-long
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_generic_invalid_url(self):
        content = '  script_xref(name:"URL", value:"www.example.com");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"www.example.com");: Invalid URL'
            " value",
            results[0].message,
        )

    def test_invalid_url_trailing_angle_bracket(self):
        content = '  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/24.0/#2407>");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"https://docs.docker.com/engine/'
            'release-notes/24.0/#2407>");: Invalid URL'
            " value (trailing '>')",
            results[0].message,
        )

    def test_invalid_url_trailing_comma(self):
        content = '  script_xref(name:"URL", value:"https://dev.mysql.com/doc/refman/5.7/en/mysql-stmt-fetch.html,");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"https://dev.mysql.com/doc/refman/5.7/en/'
            'mysql-stmt-fetch.html,");: Invalid URL'
            " value (trailing ',')",
            results[0].message,
        )

    def test_invalid_url_trailing_punctuation_mark(self):
        content = '  script_xref(name:"URL", value:"http://isec.pl/vulnerabilities/isec-0017-binfmt_elf.txt:");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"http://isec.pl/vulnerabilities/'
            'isec-0017-binfmt_elf.txt:");: Invalid URL'
            " value (trailing ':')",
            results[0].message,
        )

    def test_invalid_url_trailing_square_bracket(self):
        content = (
            '  script_xref(name:"URL", value:"https://example.com/foo/bar]");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"https://example.com/foo/bar]");: Invalid URL'
            " value (trailing ']')",
            results[0].message,
        )

    def test_invalid_url_trailing_round_bracket(self):
        content = (
            '  script_xref(name:"URL", value:"https://example.com/foo/bar)");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"https://example.com/foo/bar)");: Invalid URL'
            " value (trailing ')')",
            results[0].message,
        )

    def test_invalid_url_wrong_ending(self):
        content = '  script_xref(name:"URL", value:"https://confluence.atlassian.com/security/security-bulletin-may-21-2024-1387867145.htmll");\n'
        fake_context = self.create_file_plugin_context(
            nasl_file=self.path, file_content=content
        )
        plugin = CheckScriptXrefUrl(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            'script_xref(name:"URL", value:"https://confluence.atlassian.com/security/'
            'security-bulletin-may-21-2024-1387867145.htmll");: Invalid URL'
            " value (wrong file extension)",
            results[0].message,
        )
