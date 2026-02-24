import unittest

from troubadix.plugin import FilePlugin, FilesPlugin
from troubadix.plugins import _discover_plugins


class TestPluginDiscovery(unittest.TestCase):
    def test_dynamic_plugin_discovery(self):
        file_plugins, files_plugins = _discover_plugins()
        # Check all discovered plugins are subclasses and have a name
        for plugin in file_plugins + files_plugins:
            self.assertTrue(
                issubclass(plugin, (FilePlugin, FilesPlugin)),
                f"{plugin.__name__} is not a valid plugin subclass",
            )
            self.assertTrue(
                hasattr(plugin, "name"), f"{plugin.__name__} does not have a 'name' attribute"
            )

    def test_disabled_plugins_are_excluded(self):
        class DummyDisabledPlugin(FilePlugin):
            name = "dummy_disabled"
            is_disabled = True

        DummyDisabledPlugin.__module__ = "troubadix.plugins.dummy"

        file_plugins, _ = _discover_plugins()
        self.assertNotIn(DummyDisabledPlugin, file_plugins)

        class DummyEnabledPlugin(FilePlugin):
            name = "dummy_enabled"

        DummyEnabledPlugin.__module__ = "troubadix.plugins.dummy"

        file_plugins, _ = _discover_plugins()
        self.assertIn(DummyEnabledPlugin, file_plugins)

    def test_deep_inheritance_hierarchy(self):
        class ParentPlugin(FilePlugin):
            name = "parent"

        class ChildPlugin(ParentPlugin):
            name = "child"

        class GrandChildPlugin(ChildPlugin):
            name = "grandchild"

        ParentPlugin.__module__ = "troubadix.plugins.hierarchy"
        ChildPlugin.__module__ = "troubadix.plugins.hierarchy"
        GrandChildPlugin.__module__ = "troubadix.plugins.hierarchy"

        file_plugins, _ = _discover_plugins()

        self.assertIn(ParentPlugin, file_plugins)
        self.assertIn(ChildPlugin, file_plugins)
        self.assertIn(GrandChildPlugin, file_plugins)

    def test_is_disabled_inheritance(self):
        class BaseDisabledPlugin(FilePlugin):
            name = "base_disabled"
            is_disabled = True

        class InheritedDisabledPlugin(BaseDisabledPlugin):
            name = "inherited_disabled"

        BaseDisabledPlugin.__module__ = "troubadix.plugins.test"
        InheritedDisabledPlugin.__module__ = "troubadix.plugins.test"

        file_plugins, _ = _discover_plugins()
        self.assertNotIn(BaseDisabledPlugin, file_plugins)
        self.assertNotIn(InheritedDisabledPlugin, file_plugins)

    def test_is_disabled_override(self):
        class BaseDisabledPlugin(FilePlugin):
            name = "base_disabled"
            is_disabled = True

        class ReEnabledPlugin(BaseDisabledPlugin):
            name = "re_enabled"
            is_disabled = False

        BaseDisabledPlugin.__module__ = "troubadix.plugins.test"
        ReEnabledPlugin.__module__ = "troubadix.plugins.test"

        file_plugins, _ = _discover_plugins()
        self.assertNotIn(BaseDisabledPlugin, file_plugins)
        self.assertIn(ReEnabledPlugin, file_plugins)

    def test_files_plugin_disabled(self):
        class DisabledFilesPlugin(FilesPlugin):
            name = "disabled_files"
            is_disabled = True

        DisabledFilesPlugin.__module__ = "troubadix.plugins.test"

        _, files_plugins = _discover_plugins()
        self.assertNotIn(DisabledFilesPlugin, files_plugins)

    def test_external_plugin_exclusion(self):
        class ExternalPlugin(FilePlugin):
            name = "external"

        # Simulate a plugin defined outside the troubadix.plugins package
        ExternalPlugin.__module__ = "some_other_package.plugins"

        file_plugins, _ = _discover_plugins()
        self.assertNotIn(ExternalPlugin, file_plugins)
