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

import unittest

from naslinter.plugin import LinterError
from naslinter.plugins.valid_oid import CheckValidOID


class CheckValidOIDTestCase(unittest.TestCase):
    def test_ok(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.1.0.100376");'

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_empty_tag(self):
        path = Path("some/file.nasl")
        content = "script_oid();"

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "No valid script_oid() call found in VT 'file.nasl'",
            results[0].message,
        )

    def test_invalid_oid(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.2.0.100376");'

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 2)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() in VT 'file.nasl' is using an invalid"
                " OID '1.3.6.1.4.1.25623.2.0.100376'"
            ),
            results[0].message,
        )

        self.assertIsInstance(results[1], LinterError)
        self.assertEqual(
            (
                "script_oid() in VT 'file.nasl' is using an invalid"
                " OID '1.3.6.1.4.1.25623.2.0.100376'"
            ),
            results[0].message,
        )

    def test_missing__script_family(self):
        path = Path("some/file.nasl")
        content = 'script_oid("1.3.6.1.4.1.25623.1.1.100376");'

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            "VT 'file.nasl' is missing a script family!", results[0].message
        )

    def test_euler_family_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.2.2025.5555");'
            'script_family("Huawei EulerOS Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_euler_family(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.2.2055.5555");'
            'script_family("Huawei EulerOS Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() in VT 'file.nasl' is using an invalid OID "
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

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_suse_family(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2025.555755.5");'
            'script_family("SuSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "script_oid() in VT 'file.nasl' "
                "is using an invalid OID '1.3.6.1.4.1.25623.1.1.4.2025.555755"
                ".5' (SLES pattern: 1.3.6.1.4.1.25623.1.1.4.[ADVISORY_YEAR]."
                "[ADVISORY_ID].[ADVISORY_REVISION])"
            ),
            results[0].message,
        )

    def test_debian_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.1.2256");'
            'script_family("Debian Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_debian(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.1.2256");'
            'script_family("Suse Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                " Debian VTs'1.3.6.1.4.1.25623.1.1.1.2256'"
            ),
            results[0].message,
        )

    def test_centos_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.3.2256");'
            'script_family("CentOS Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_centos(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.3.2256");'
            'script_family("Suse Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "CentOS VTs '1.3.6.1.4.1.25623.1.1.3.2256'"
            ),
            results[0].message,
        )

    def test_centos_or_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2256");'
            'script_family("CentOS Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_centos_or(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.4.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "CentOS_CR VTs '1.3.6.1.4.1.25623.1.1.4.2256'"
            ),
            results[0].message,
        )

    def test_fedora_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.5.2256");'
            'script_family("Fedora Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_fedora(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.5.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Fedora VTs '1.3.6.1.4.1.25623.1.1.5.2256'"
            ),
            results[0].message,
        )

    def test_gentoo_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.6.2256");'
            'script_family("Gentoo Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_gentoo(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.6.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Gentoo VTs '1.3.6.1.4.1.25623.1.1.6.2256'"
            ),
            results[0].message,
        )

    def test_hpux_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.7.2256");'
            'script_family("HP-UX Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_hpux(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.7.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "HP-UX VTs '1.3.6.1.4.1.25623.1.1.7.2256'"
            ),
            results[0].message,
        )

    def test_mandrake_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.8.2256");'
            'script_family("Mandrake Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_mandrake(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.8.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Mandrake/Mandriva VTs '1.3.6.1.4.1.25623.1.1.8.2256'"
            ),
            results[0].message,
        )

    def test_opensuse_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.9.2256");'
            'script_family("SuSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_opensuse(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.9.2256");'
            'script_family("Debian Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "openSUSE VTs '1.3.6.1.4.1.25623.1.1.9.2256'"
            ),
            results[0].message,
        )

    def test_redhat_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.10.2256");'
            'script_family("Red Hat Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_redhat(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.10.2256");'
            'script_family("Debian Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Red Hat VTs '1.3.6.1.4.1.25623.1.1.10.2256'"
            ),
            results[0].message,
        )

    def test_solaris_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.11.2256");'
            'script_family("Solaris Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_solaris(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.11.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Solaris VTs '1.3.6.1.4.1.25623.1.1.11.2256'"
            ),
            results[0].message,
        )

    def test_suse_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.12.2256");'
            'script_family("SuSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_suse(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.12.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "SUSE VTs '1.3.6.1.4.1.25623.1.1.12.2256'"
            ),
            results[0].message,
        )

    def test_ubuntu_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.13.2256");'
            'script_family("Ubuntu Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)

    def test_ubuntu(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.13.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an OID that is reserved for "
                "Ubuntu VTs '1.3.6.1.4.1.25623.1.1.13.2256'"
            ),
            results[0].message,
        )

    def test_unknown(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.14.2256");'
            'script_family("SUSE Local Security Checks");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 1)

        self.assertIsInstance(results[0], LinterError)
        self.assertEqual(
            (
                "VT 'file.nasl' is using an invalid OID '1.3.6.1.4.1.25623."
                "1.1.14.2256' (Vendor OID with unknown Vendor-Prefix)"
            ),
            results[0].message,
        )

    def test_script_name_ok(self):
        path = Path("some/file.nasl")
        content = (
            'script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2555");'
            'script_family("Huawei EulerOS Local Security Checks");'
            'script_name("AdaptBB Detection (HTTP)");'
        )

        results = list(CheckValidOID.run(path, content))
        self.assertEqual(len(results), 0)
