# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Greenbone AG
import io
import os
import unittest
from contextlib import redirect_stderr
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
            infos=["cross-feed"],
            warnings=["duplicate dependencies"],
            errors=["missing dependencies"],
        )

    def test_output_formatting(self):
        with self.assertLogs("troubadix", level="INFO") as log:
            reporter = Reporter()
            reporter.report([self.result])

            self.assertEqual("INFO", log.records[2].levelname)
            self.assertEqual(
                "TestScript: cross-feed",
                log.records[2].message,
            )
            self.assertEqual("WARNING", log.records[1].levelname)
            self.assertEqual(
                "TestScript: duplicate dependencies",
                log.records[1].message,
            )
            self.assertEqual("ERROR", log.records[0].levelname)
            self.assertEqual(
                "TestScript: missing dependencies",
                log.records[0].message,
            )


class TestCLIArgs(unittest.TestCase):
    @patch(
        "sys.argv",
        [
            "prog",
            "--root",
            "tests/standalone_plugins/nasl",
            "--feed",
            "22.04",
            "--log",
            "info",
        ],
    )
    def test_parse_args_ok(self):
        args = parse_args()
        self.assertEqual(args.root, Path("tests/standalone_plugins/nasl"))
        self.assertEqual(args.feed, Feed.FEED_22_04)
        self.assertEqual(args.log, "INFO")

    @patch("sys.argv", ["prog", "--root", "not_real_dir"])
    def test_parse_args_no_dir(self):
        with redirect_stderr(io.StringIO()) as f:
            with self.assertRaises(SystemExit):
                parse_args()
        self.assertRegex(f.getvalue(), "invalid directory_type")

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
    def test_parse_args_invalid_feed(self):
        with self.assertRaises(SystemExit):
            parse_args()

    @patch.dict(os.environ, {"VTDIR": "/mock/env/path"})
    @patch("sys.argv", ["prog"])
    def test_parse_args_with_env(self):
        args = parse_args()
        self.assertEqual(args.root, Path("/mock/env/path"))

    @patch("sys.argv", ["prog", "--root", "tests/standalone_plugins/nasl"])
    def test_parse_args_defaults(self):
        args = parse_args()
        self.assertEqual(args.log, "WARNING")
        self.assertEqual(args.feed, Feed.COMMON)


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
        feed = Feed.FEED_22_04
        scripts = get_feed(Path(self.local_root), feed)
        self.assertEqual(len(scripts), 5)

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

    @patch(
        "sys.argv",
        ["prog", "--root", "tests/standalone_plugins/nasl", "--log", "info"],
    )
    def test_full_run(self):
        with self.assertLogs("troubadix", level="INFO") as log:
            return_code = main()

            self.assertEqual("ERROR", log.records[4].levelname)
            self.assertEqual(
                "missing dependency: missing.nasl:\n  - used by: foo.nasl",
                log.records[4].message,
            )

            self.assertEqual("ERROR", log.records[5].levelname)
            self.assertRegex(
                log.records[5].message,
                "cyclic dependency: "
                r"\['(foo|bar|foobar).nasl', '(foo|bar|foobar).nasl', '(foo|bar|foobar).nasl'\]",
            )

            self.assertEqual("ERROR", log.records[6].levelname)
            self.assertEqual(
                "cross-feed dependency: incorrect feed check in foo.nasl(community feed) "
                "which depends on gsf/enterprise_script.nasl(enterprise feed)",
                log.records[6].message,
            )

            self.assertEqual("ERROR", log.records[8].levelname)
            self.assertEqual(
                "category order: bar.nasl depends on foo.nasl which has a lower category order",
                log.records[8].message,
            )

            self.assertEqual("ERROR", log.records[9].levelname)
            self.assertEqual(
                "deprecated dependency: foo.nasl depends on deprecated script foobar.nasl",
                log.records[9].message,
            )

            self.assertEqual("WARNING", log.records[3].levelname)
            self.assertEqual(
                "duplicate dependency: in bar.nasl: foo.nasl",
                log.records[3].message,
            )

            self.assertEqual("INFO", log.records[7].levelname)
            self.assertEqual(
                "cross-feed dependency: bar.nasl(community feed) depends "
                "on gsf/enterprise_script.nasl(enterprise feed)",
                log.records[7].message,
            )

            self.assertEqual(return_code, 1)
