# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from troubadix.standalone_plugins.dependency_graph.cli import parse_args
from troubadix.standalone_plugins.dependency_graph.dependency_graph import (
    create_graph,
    get_feed,
    main,
)
from troubadix.standalone_plugins.dependency_graph.models import (
    Dependency,
    Feed,
    Script,
)

NASL_DIR = "tests/standalone_plugins/nasl"


class TestDependencyGraph(unittest.TestCase):

    def test_parse_args_ok(self):
        test_args = [
            "prog",
            NASL_DIR,
            "--feed",
            "feed_22_04",
            "--log",
            "info",
        ]
        with patch.object(sys, "argv", test_args):
            args = parse_args()
            self.assertTrue(args)
            self.assertEqual(args.root, Path(NASL_DIR))
            self.assertEqual(args.feed, [Feed.FEED_22_04])
            self.assertEqual(args.log, "info")

    @patch("sys.stderr", new_callable=StringIO)
    def test_parse_args_no_dir(self, mock_stderr):
        test_args = ["prog", "not_real_dir"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit):
                parse_args()
            self.assertRegex(mock_stderr.getvalue(), "invalid directory_type")

    def test_get_feed(self):
        feed = [Feed.FULL]
        scripts = get_feed(Path(NASL_DIR), feed)
        self.assertEqual(len(scripts), 6)

    def test_create_graph(self):
        dependency1 = Dependency("bar.nasl", False)
        scripts = [
            Script("foo.nasl", "community", [dependency1], 0, False),
            Script("bar.nasl", "enterprise", [], 0, False),
        ]
        graph = create_graph(scripts)
        self.assertEqual(len(list(graph.nodes)), 2)

    def test_full_run(self):
        test_args = [
            "prog",
            NASL_DIR,
        ]
        with (
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
            patch.object(sys, "argv", test_args),
        ):
            return_code = main()
            self.assertEqual(return_code, 1)
