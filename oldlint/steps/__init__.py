from os.path import dirname, basename, isfile
import glob
import os

"""
Automatic import of all qa-scripts for further usage in the master script.
New checks can simply added to this directory.
"""
modules = glob.glob(dirname(__file__) + "/*.py")
__all__ = [
    basename(f)[:-3]
    for f in modules
    if isfile(f) and not f.endswith("__init__.py")
]
