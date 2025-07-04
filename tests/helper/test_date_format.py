# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG

from unittest import TestCase

from troubadix.helper.date_format import check_date


class CheckCreationDateTestCase(TestCase):

    def test_ok(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55 +0200 (Tue, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(results, [])

    def test_missing(self):
        results = list(
            check_date(
                None,
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "No test_date has been found.",
            results[0].message,
        )

    def test_wrong_weekday(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55 +0200 (Mon, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Wrong day of week. Please change it from 'Mon' to 'Tue'.",
            results[0].message,
        )

    def test_no_timezone(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55 (Tue, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing or incorrectly formatted test_date.",
            results[0].message,
        )

    def test_different_dates(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55 +0200 (Wed, 15 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "The test_date consists of two different dates.",
            results[0].message,
        )

    def test_wrong_length(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55 +0200 (Wed, 15 May 2013) ",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "The test_date consists of two different dates.",
            results[0].message,
        )

    def test_malformed_second(self):
        results = list(
            check_date(
                "2013-05-14 11:24:55s +0200 (Tue, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing or incorrectly formatted test_date.",
            results[0].message,
        )

    def test_malformed_hour(self):
        results = list(
            check_date(
                "2013-05-14 111:24:55 +0200 (Tue, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing or incorrectly formatted test_date.",
            results[0].message,
        )

    def test_malformed_day(self):
        results = list(
            check_date(
                "2013-05-14d 11:24:55 +0200 (Tue, 14 May 2013)",
                "test_date",
                "test_file",
                "test_plugin",
            )
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(
            "Missing or incorrectly formatted test_date.",
            results[0].message,
        )
