# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import os
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from troubadix.plugins.dependency_category_order import VTCategory
from troubadix.standalone_plugins.dependency_graph.cli import parse_args
from troubadix.standalone_plugins.dependency_graph.dependency_graph import (
    Reporter,
    create_graph,
    determine_feed,
    extract_category,
    extract_dependencies,
    get_feed,
    get_scripts,
    main,
)
from troubadix.standalone_plugins.dependency_graph.models import (
    Dependency,
    Feed,
    Result,
    Script,
)


class TestReporter(unittest.TestCase):
    def setUp(self):
        self.result = Result(
            name="TestScript",
            warnings=["duplicate dependencies"],
            errors=["missing dependencies"],
        )

    @patch("sys.stdout", new_callable=StringIO)
    def test_report_verbosity_2(self, mock_stdout):
        reporter = Reporter(verbosity=2)
        reporter.report([self.result])

        output = mock_stdout.getvalue()

        self.assertIn("TestScript - warnings: 1, errors: 1", output)
        self.assertIn("warning: duplicate dependencies", output)
        self.assertIn("error: missing dependencies", output)


class TestCLIArgs(unittest.TestCase):
    @patch(
        "sys.argv",
        [
            "prog",
            "--root",
            "tests/standalone_plugins/nasl",
            "--feed",
            "feed_22_04",
            "--log",
            "info",
        ],
    )
    def test_parse_args_ok(self):
        args = parse_args()
        self.assertEqual(args.root, Path("tests/standalone_plugins/nasl"))
        self.assertEqual(args.feed, [Feed.FEED_22_04])
        self.assertEqual(args.log, "info")

    @patch("sys.stderr", new_callable=StringIO)
    @patch("sys.argv", ["prog", "--root", "not_real_dir"])
    def test_parse_args_no_dir(self, mock_stderr):
        with self.assertRaises(SystemExit):
            parse_args()
        self.assertRegex(mock_stderr.getvalue(), "invalid directory_type")

    @patch("sys.stderr", new_callable=StringIO)
    @patch(
        "sys.argv",
        [
            "prog",
            "--root",
            "tests/standalone_plugins/nasl",
            "--feed",
            "invalid_feed",
        ],
    )
    def test_parse_args_invalid_feed(self, mock_stderr):
        with self.assertRaises(SystemExit):
            parse_args()
        self.assertRegex(mock_stderr.getvalue(), "Invalid Feed value")

    @patch.dict(os.environ, {"VTDIR": "/mock/env/path"})
    @patch("sys.argv", ["prog"])
    def test_parse_args_with_env(self):
        args = parse_args()
        self.assertEqual(args.root, Path("/mock/env/path"))

    @patch("sys.argv", ["prog", "--root", "tests/standalone_plugins/nasl"])
    def test_parse_args_defaults(self):
        args = parse_args()
        self.assertEqual(args.log, "WARNING")
        self.assertEqual(args.feed, [Feed.FULL])


class TestDependencyGraph(unittest.TestCase):

    def setUp(self) -> None:
        self.local_root = "tests/standalone_plugins/nasl"
        self.script_content = """
if(description)
{
  script_category(ACT_GATHER_INFO);
  script_dependencies( "foo.nasl", "foo.nasl" );

  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/enterprise_script.nasl");

  exit(0);
}
        """

    def test_get_feed(self):
        feed = [Feed.FULL]
        scripts = get_feed(Path(self.local_root), feed)
        self.assertEqual(len(scripts), 6)

    @patch("pathlib.Path.read_text")
    def test_get_scripts(self, mock_read_text):
        mock_read_text.return_value = self.script_content
        scripts = get_scripts(Path(self.local_root) / "common")
        self.assertEqual(len(scripts), 4)
        self.assertEqual(scripts[0].feed, "community")
        self.assertEqual(len(scripts[0].dependencies), 3)
        self.assertEqual(scripts[0].category, VTCategory.ACT_GATHER_INFO)
        self.assertEqual(scripts[0].deprecated, False)

    def test_determine_feed(self):
        community_script = Path("foo/script.nasl")
        enterprise_script = Path("gsf/script.nasl")

        self.assertEqual(determine_feed(community_script), "community")
        self.assertEqual(determine_feed(enterprise_script), "enterprise")

    def test_extract_dependencies(self):
        dependencies = extract_dependencies(self.script_content)
        self.assertEqual(len(dependencies), 3)
        self.assertEqual(dependencies[0].name, "foo.nasl")
        self.assertEqual(dependencies[1].name, "foo.nasl")
        self.assertEqual(dependencies[2].name, "gsf/enterprise_script.nasl")
        self.assertEqual(dependencies[0].is_enterprise_feed, False)
        self.assertEqual(dependencies[1].is_enterprise_feed, False)
        self.assertEqual(dependencies[2].is_enterprise_feed, True)

    def test_extract_category(self):
        category = extract_category(self.script_content)
        self.assertEqual(category, VTCategory.ACT_GATHER_INFO)

    def test_create_graph(self):
        dependency1 = Dependency("bar.nasl", False)
        scripts = [
            Script("foo.nasl", "community", [dependency1], 0, False),
            Script("bar.nasl", "enterprise", [], 0, False),
        ]
        graph = create_graph(scripts)
        self.assertEqual(len(list(graph.nodes)), 2)

    @patch("sys.stdout", new_callable=StringIO)  # mock_stdout (second argument)
    @patch("sys.stderr", new_callable=StringIO)  # mock_stderr (first argument)
    @patch(
        "sys.argv", ["prog", "--root", "tests/standalone_plugins/nasl", "-v"]
    )  # no argument
    def test_full_run(self, mock_stderr, mock_stdout):
        return_code = main()
        output = mock_stdout.getvalue()

        self.assertIn("error: missing dependency file: missing.nasl:", output)
        self.assertIn(
            "error: cyclic dependency: ",  # order is random so can't match the output
            output,
        )
        self.assertIn(
            "error: unchecked cross-feed-dependency: foo.nasl(community feed) depends on"
            " gsf/enterprise_script.nasl(enterprise feed), but the"
            " current feed is not properly checked",
            output,
        )
        self.assertIn(
            "error: bar.nasl depends on foo.nasl which has a lower category order",
            output,
        )
        self.assertIn(
            "error: foo.nasl depends on deprecated script foobar.nasl", output
        )
        self.assertIn(
            "warning: Duplicate dependencies in bar.nasl: foo.nasl", output
        )
        self.assertIn(
            "warning: cross-feed-dependency: bar.nasl(community feed)"
            " depends on gsf/enterprise_script.nasl(enterprise feed)",
            output,
        )
        self.assertEqual(return_code, 1)
