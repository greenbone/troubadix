#  Copyright (c) 2022 Greenbone AG
#
#  SPDX-License-Identifier: GPL-3.0-or-later
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.


from pathlib import Path

from troubadix.plugin import LinterError
from troubadix.plugins.http_links_in_tags import CheckHttpLinksInTags

from . import PluginTestCase


class CheckHttpLinksInTagsTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            'port = get_app_port_from_cpe_prefix("cpe:/o:foo:bar");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckHttpLinksInTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckHttpLinksInTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_not_ok(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar. '
            'https://www.website.de/demo");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckHttpLinksInTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "One script_tag in the VT is using a "
            "HTTP link/URL which should be moved to a separate "
            '\'script_xref(name:"URL", value:"");\' tag instead: '
            '\'script_tag(name:"summary", value:"Foo Bar. '
            "https://www.website.de/demo\");'",
            results[0].message,
        )

    def test_not_ok2(self):
        path = Path("some/file.nasl")
        content = (
            '  script_tag(name:"cvss_base", value:"4.0");\n'
            '  script_tag(name:"summary", value:"Foo Bar.");\n'
            '  script_tag(name:"solution_type", value:"VendorFix");\n'
            '  script_tag(name:"solution", value:"meh");\n'
            '  script_xref(name:"URL", '
            'value:"https://nvd.nist.gov/vuln/detail/CVE-1234");\n'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckHttpLinksInTags(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "The following script_xref is pointing "
            "to Mitre/NVD which is already covered by the script_cve_id. "
            "This is a redundant info and the script_xref needs to be "
            'removed: script_xref(name:"URL", '
            'value:"https://nvd.nist.gov/vuln/detail/CVE-1234");',
            results[0].message,
        )

    def test_http_link_in_tags_ok(self):
        testcases = [
            "01. The payloads try to open a connection to www.google.com",
            "02. The script attempts to connect to www.google.com",
            "03. to retrieve a web page from www.google.com",
            "04. Subject: commonName=www.paypal.com",
            "05. Terms of use at https://www.verisign.com/rpa",
            "06. example.com",
            "07. example.org",
            "08. www.exam",
            "09. sampling the resolution of a name (www.google.com)",
            "10. once with 'www.' and once without",
            "11. wget http://www.javaop.com/~ron/tmp/nc",
            "12. as www.windowsupdate.com. (BZ#506016)",
            "13. located at http://sambarserver/session/pagecount.",
            "14. http://rest.modx.com",
            "15. ftp:// ",
            "16. ftp://'",
            "17. ftp://)",
            "18. ftp.c",
            "19. ftp.exe",
            "20. using special ftp://",
            "21. running ftp.",
            "22. ftp. The vulnerability",
            "23. 'http://' protocol",
            "24. handle <a href='http://...'> properly",
            "25. Switch to git+https://",
            "26. wget https://compromised-domain.com/important-file",
            "27. the https:// scheme",
            "28. https://www.phishingtarget.com@evil.com",
            "29. 'http://'",
            "30. 'https://'",
            "31. distributions on ftp.proftpd.org have all been",
            "32. information from www.mutt.org:",
            "33. According to www.tcpdump.org:",
            "34. According to www.kde.org:",
            "35. From the www.info-zip.org site:",
            # pylint: disable=line-too-long
            "36.  (www.isg.rhul.ac.uk) for discovering this flaw and Adam Langley and",
            "37. Sorry about having to reissue this one -- I pulled it from ftp.gnu.org not",
            "38. http://internal-host$1 is still insecure",
            "39. from online sources (ftp://, http:// etc.).",
            "40. this and https:// and that.",
            "41. such as 'http://:80'",
            "42. <http://localhost/moodle/admin/>",
        ]

        for testcase in testcases:
            self.assertTrue(CheckHttpLinksInTags.check_to_continue(testcase))

    def test_http_link_in_tags_not_ok(self):
        testcases = [
            "The payloads try to open a connection to www.bing.com",
            "examplephishing.org",
            "located at http://sambdadancinglessions/session/pagecount.",
            "fdp:// ",
            "Switch to svn+https://",
            "greenbone.net",
        ]

        for testcase in testcases:
            self.assertFalse(CheckHttpLinksInTags.check_to_continue(testcase))
