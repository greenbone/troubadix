# Copyright (C) 2022 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Iterator

import magic

from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterResult,
)

ALLOWED_ENCODINGS = ["iso-8859-1", "us-ascii"]


class CheckEncoding(FilePlugin):
    name = "check_encoding"

    def run(self) -> Iterator[LinterResult]:
        with open(self.context.nasl_file, "rb") as f:
            raw = f.read()

        # Use magic to detect encoding
        m = magic.Magic(mime_encoding=True)
        detected_encoding = m.from_buffer(raw)

        if detected_encoding not in ALLOWED_ENCODINGS:
            yield LinterError(
                f"File encoding detected as '{detected_encoding}' (not Latin1-compatible).",
                file=self.context.nasl_file,
                plugin=self.name,
            )

        # Function to detect UTF-8 multibyte sequences
        def has_utf8_multibyte(data: bytes) -> bool:
            i = 0
            while i < len(data) - 1:
                first = data[i]
                second = data[i + 1]
                if 0xC2 <= first <= 0xF4 and 0x80 <= second <= 0xBF:
                    return True
                i += 1
            return False

        lines = raw.split(b"\n")
        for i, line_bytes in enumerate(lines, start=1):
            if has_utf8_multibyte(line_bytes):
                yield LinterError(
                    f"Likely UTF-8 multibyte sequence found in line {i}",
                    file=self.context.nasl_file,
                    plugin=self.name,
                    line=i,
                )
