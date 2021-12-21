#!/usr/bin/env python3

"""
This scripts include functions shared in many steps
for gitlab CI.
"""

import sys
import subprocess
import os
import re


def subprocess_cmd(command):
    """
    Run a command on a shell and return the output.

    Args:
        command: Command to run on shell

    Returns:
        list: Output from command as list of strings
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


def list_modified_files():
    """
    Get a list of nasl and inc files which are different to master.

    Returns:
        list: Files different to origin/master
    """
    try:
        modified_files = []
        pattern = re.compile("^([MA]\s+|R[0-9]+\s+[^\s]+\s)(.+\.(inc|nasl))$")
        with open(sys.argv[1], "r") as files:
            for line in files.readlines():
                file = pattern.match(line)
                if file:
                    modified_files.append(file.group(2))

        if len(modified_files) > 0:
            return modified_files
        else:
            return None
    except:
        print("error")
        return None


def report(message, files=None):
    """
    Print error or warning message. If no files given, only message is shown

    Args:
        message: Text for reporting
        files (optional): filelist to show after message
    """
    if not message:
        print("I don't know anything to show!")
    else:
        print(message, ":")
        if files is not None:
            print("\n".join(files))


def filepath_without_scripts_dir(file_path):
    """
    Remove the script directory at beginning of file_path. This is needed for bitchy openvas-nasl-lint.

    Args:
        file_path: The path where to remove "scripts/" from
    """
    path, file = os.path.split(file_path)
    if path.startswith("scripts/"):
        path = path.replace("scripts/", "", 1)
    if path == "scripts":
        path = path.replace("scripts", "", 1)

    return os.path.join(path, file)
