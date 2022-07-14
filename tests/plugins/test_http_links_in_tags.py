#  Copyright (c) 2022 Greenbone Networks GmbH
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
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'get_app_port_from_cpe_prefix("cpe:/o:foo:bar");\n'
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
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar. '
            'https://www.website.de/demo");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
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
            'script_tag(name:"cvss_base", value:"4.0");\n'
            'script_tag(name:"summary", value:"Foo Bar.");\n'
            'script_tag(name:"solution_type", value:"VendorFix");\n'
            'script_tag(name:"solution", value:"meh");\n'
            'script_xref(name:"URL", '
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
            "12. Ncat: Version 5.30BETA1 (http://nmap.org/ncat)",
            "13. as www.windowsupdate.com. (BZ#506016)",
            "14. located at http://sambarserver/session/pagecount.",
            "15. http://rest.modx.com",
            "16. ftp:// ",
            "17. ftp://'",
            "18. ftp://)",
            "19. ftp.c",
            "20. ftp.exe",
            "21. using special ftp://",
            "22. running ftp.",
            "23. ftp. The vulnerability",
            "24. 'http://' protocol",
            "25. handle <a href='http://...'> properly",
            "26. Switch to git+https://",
            "27. wget https://compromised-domain.com/important-file",
            "28. the https:// scheme",
            "29. https://www.phishingtarget.com@evil.com",
            "30. 'http://'",
            "31. 'https://'",
            "32. distributions on ftp.proftpd.org have all been",
            "33. information from www.mutt.org:",
            "34. According to www.tcpdump.org:",
            "35. According to www.kde.org:",
            "36. From the www.info-zip.org site:",
            # pylint: disable=line-too-long
            "37.  (www.isg.rhul.ac.uk) for discovering this flaw and Adam Langley and",
            "38. Sorry about having to reissue this one -- I pulled it from ftp.gnu.org not",
            "39. http://internal-host$1 is still insecure",
            "40. from online sources (ftp://, http:// etc.).",
            "41. this and https:// and that.",
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
