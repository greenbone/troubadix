# Copyright (c) 2022 Greenbone Networks GmbH
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

from troubadix.plugin import LinterError
from troubadix.plugins.valid_oid import CheckValidOID

from . import PluginTestCase


class CheckValidOIDTestCase(PluginTestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.1.0.100376");'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_exclude_inc_file(self):
        path = Path("some/file.inc")
        fake_context = self.create_file_plugin_context(nasl_file=path)
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_empty_tag(self):
        path = Path("some/file.nasl")
        content = "script_oid();"
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "No valid script_oid() call found",
            results[0].message,
        )

    def test_invalid_oid(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.2.0.100376");'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid "
                "OID '1.3.6.1.4.1.25623.2.0.100376'"
            ),
            results[0].message,
        )

    def test_missing__script_family(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.1.1.100376");'
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual("VT is missing a script family!", results[0].message)

    def test_euler_family_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.2.2025.5555");'
            'script_family("Huawei EulerOS Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_euler_family(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.2.2055.5555");'
            'script_family("Huawei EulerOS Local Security Checks");'
        )

        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid OID "
                "'1.3.6.1.4.1.25623.1.1.2.2055.5555' (EulerOS pattern:"
                " 1.3.6.1.4.1.25623.1.1.2.[ADVISORY_YEAR].[ADVISORY_ID])"
            ),
            results[0].message,
        )

    def test_suse_family_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2025.55555.5");'
            'script_family("SuSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_suse_family(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2025.555755.5");'
            'script_family("SuSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid OID '1.3.6.1.4.1.25623.1.1."
                "4.2025.555755.5' (SLES pattern: 1.3.6.1.4.1.25623.1.1.4"
                ".[ADVISORY_YEAR].[ADVISORY_ID].[ADVISORY_REVISION])"
            ),
            results[0].message,
        )

    def test_debian_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.1.2256");'
            'script_family("Debian Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_debian(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.1.2256");'
            'script_family("Suse Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Debian '1.3.6.1.4.1.25623.1.1.1.2256'"
            ),
            results[0].message,
        )

    def test_unused_oid(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.3.2256");'
            'script_family("Suse Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid OID '1.3.6.1.4.1.25623.1.1"
                ".3.2256' (Vendor OID with unknown Vendor-Prefix)"
            ),
            results[0].message,
        )

    def test_suse_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2012.2256.1");'
            'script_family("SuSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_suse(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "SUSE SLES '1.3.6.1.4.1.25623.1.1.4.2256'"
            ),
            results[0].message,
        )

    def test_amazon_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.5.2012.2256");'
            'script_family("Amazon Linux Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_amazon(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.5.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Amazon Linux '1.3.6.1.4.1.25623.1.1.5.2256'"
            ),
            results[0].message,
        )

    def test_gentoo_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.6.2256");'
            'script_family("Gentoo Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_gentoo(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.6.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Gentoo '1.3.6.1.4.1.25623.1.1.6.2256'"
            ),
            results[0].message,
        )

    def test_freebsd_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.7.2256");'
            'script_family("FreeBSD Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_freebsd(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.7.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "FreeBSD '1.3.6.1.4.1.25623.1.1.7.2256'"
            ),
            results[0].message,
        )

    def test_oracle_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.8.2256");'
            'script_family("Oracle Linux Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_oracle(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.8.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Oracle Linux '1.3.6.1.4.1.25623.1.1.8.2256'"
            ),
            results[0].message,
        )

    def test_fedora_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.9.2256");'
            'script_family("Fedora Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_fedora(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.9.2256");'
            'script_family("Debian Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Fedora '1.3.6.1.4.1.25623.1.1.9.2256'"
            ),
            results[0].message,
        )

    def test_mageia_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.10.2012.2256");'
            'script_family("Mageia Linux Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_mageia(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.10.2256");'
            'script_family("Debian Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Mageia Linux '1.3.6.1.4.1.25623.1.1.10.2256'"
            ),
            results[0].message,
        )

    def test_redhat_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.11.2256");'
            'script_family("RedHat Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_redhat(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.11.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "RedHat '1.3.6.1.4.1.25623.1.1.11.2256'"
            ),
            results[0].message,
        )

    def test_ubuntu_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.12.2012.2256.1");'
            'script_family("Ubuntu Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_ubuntu(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.12.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Ubuntu '1.3.6.1.4.1.25623.1.1.12.2256'"
            ),
            results[0].message,
        )

    def test_slackware_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.13.2022.123.01");'
            'script_family("Slackware Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_slackware(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.13.2022.123.01");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Slackware '1.3.6.1.4.1.25623.1.1.13.2022.123.01'"
            ),
            results[0].message,
        )

    def test_rocky_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.14.2022.123");'
            'script_family("Rocky Linux Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_rocky(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.14.2022.123");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for "
                "Rocky Linux '1.3.6.1.4.1.25623.1.1.14.2022.123'"
            ),
            results[0].message,
        )

    def test_unknown(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.99.2256");'
            'script_family("SUSE Local Security Checks");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid OID '1.3.6.1.4.1.25623.1.1."
                "99.2256' (Vendor OID with unknown Vendor-Prefix)"
            ),
            results[0].message,
        )

    def test_script_name__product_unknown(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.2.2025.2555");'
            'script_family("Huawei EulerOS Local Security Checks");'
            'script_name("AdaptBB Detection (HTTP)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an invalid OID '1.3.6.1.4.1.25623.1.2"
                ".2025.2555' (last digits)"
            ),
            results[0].message,
        )

    def test_script_name__product_firefox_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.2.1.2020.255");'
            'script_name("Mozilla Firefox Security Advisory");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 0)

    def test_script_name__product_firefox(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.2.1.2020.255");'
            'script_name("AdaptBB Detection (HTTP)");'
        )
        fake_context = self.create_file_plugin_context(
            nasl_file=path, file_content=content
        )
        plugin = CheckValidOID(fake_context)

        results = list(plugin.run())

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() is using an OID that is reserved for 'Firefox' "
                "(1.3.6.1.4.1.25623.1.2.1.2020.255)"
            ),
            results[0].message,
        )
