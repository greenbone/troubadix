# Copyright (C) 2022 Greenbone AG
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Iterator

import magic

from troubadix.plugin import (
    FilePlugin,
    LinterError,
    LinterResult,
)

# OpenVAS decodes NASL files using ISO-8859-1 (Latin-1).
# Files saved in other encodings (like UTF-8)
# will be misinterpreted and cause errors or garbled text.
# US-ASCII is also allowed since it's a subset of ISO-8859-1.
ALLOWED_ENCODINGS = ["iso-8859-1", "us-ascii"]


class CheckEncoding(FilePlugin):
    """
    Check if the encoding of the NASL file is ISO-8859-1 (Latin-1) encoded.
    Finds UTF-8 multibyte sequences that are composed of individually valid Latin-1 bytes,
    but result in garbled text.
    """

    name = "check_encoding"

    def run(self) -> Iterator[LinterResult]:
        with open(self.context.nasl_file, "rb") as f:
            raw = f.read()

        # Use magic to detect encoding
        detected_encoding = magic.Magic(mime_encoding=True).from_buffer(raw)

        if detected_encoding not in ALLOWED_ENCODINGS:
            yield LinterError(
                f"Detected encoding '{detected_encoding.upper()}' is not Latin-1 compatible.",
                file=self.context.nasl_file,
                plugin=self.name,
            )

        def has_utf8_multibyte(data: bytes) -> bool:
            """
            Function to detect UTF-8 multibyte sequences by checking the first two bytes.
            UTF-8 multibyte sequences start with a lead byte followed by continuation bytes.

            Lead byte ranges:
            - 2-byte: 0xC2–0xDF (110xxxxx, excluding 0xC0–0xC1 to avoid overlongs)
            - 3-byte: 0xE0–0xEF (1110xxxx)
            - 4-byte: 0xF0–0xF4 (11110xxx)
            These ranges are continuous, so we can check 0xC2–0xF4 as a single range.
            11000010  C2  --  F4  11110111

            Continuation bytes: 0x80–0xBF (10yyyyyy)
            10000000  80  --  BF  10111111

            Lead and continuation byte values are either not valid Latin-1 or special symbols
            that are unlikely to be following each other in normal use.
            """

            for i in range(len(data) - 1):
                first = data[i]
                second = data[i + 1]
                if 0xC2 <= first <= 0xF4 and 0x80 <= second <= 0xBF:
                    return True
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
