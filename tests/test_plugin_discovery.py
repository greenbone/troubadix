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
