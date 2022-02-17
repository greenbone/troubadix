#!/usr/bin/env python3

import subprocess
import re
from pathlib import Path
from typing import Iterator

# import magic

from naslinter.plugin import FileContentPlugin, LinterError, LinterResult


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


class CheckEncoding(FileContentPlugin):
    name = "check_encoding"

    @staticmethod
    def run(nasl_file: Path, file_content: str) -> Iterator[LinterResult]:
        # Looking for VTs with wrong encoding...
        # m = magic.Magic(mime_encoding=True)
        # encoding = m.from_buffer(file_content)
        # if not encoding == "latin-1" and not encoding == "us-ascii":
        #     yield LinterError(f"VT '{nasl_file}' has a wrong encoding.")

        # nb: The above code currently has some issues to detect the encoding so
        # it is currently temporary replaced by this function.
        encoding = subprocess_cmd(
            f"LC_ALL=C file {nasl_file} | grep 'UTF-8'"
        ).decode("latin-1")
        if len(encoding) > 0:
            yield LinterError(f"VT '{nasl_file}' has a wrong encoding.")

        # Checking characters line by line
        lines = file_content.splitlines()

        for index, line in enumerate(lines):
            # Only the ASCII and extended ASCII for now...
            # https://www.ascii-code.com/
            # encoding = re.search('[^\x00-\xFF]', line)
            # Temporary only check for chars in between 7f-9f
            # like in the old Feed-QA...
            encoding = re.search("[\x7F-\x9F]", line)
            if encoding is not None:
                yield LinterError(f"Found unvalid character in line {index}")
