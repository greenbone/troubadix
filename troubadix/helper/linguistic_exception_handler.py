# Copyright (C) 2021-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
from abc import ABC, abstractmethod
from typing import Iterable, List, Tuple, Union


class LinguisticCheck(ABC):
    @abstractmethod
    def execute(self, file_path: str, correction: str):
        pass


class FileCheck(LinguisticCheck):
    def __init__(self, file: str) -> None:
        self.file = file

    def execute(self, file_path: str, correction: str) -> bool:
        return self.file in file_path


class FilesCheck(LinguisticCheck):
    def __init__(self, files: List[str]) -> None:
        self.files = files

    def execute(self, file_path: str, correction: str):
        return any(_file in file_path for _file in self.files)


class FilePatternCheck(LinguisticCheck):
    def __init__(self, file_pattern: str, flags: re.RegexFlag = 0) -> None:
        self.file_pattern = re.compile(file_pattern, flags=flags)

    def execute(self, file_path: str, correction: str):
        return bool(self.file_pattern.search(file_path))


class TextCheck(LinguisticCheck):
    def __init__(self, text: str) -> None:
        self.text = text

    def execute(self, file_path: str, correction: str):
        return self.text in correction


class PatternCheck(LinguisticCheck):
    def __init__(self, pattern: str, flags: re.RegexFlag = 0) -> None:
        self.pattern = re.compile(pattern, flags=flags)

    def execute(self, file_path: str, correction: str):
        return bool(self.pattern.search(correction))


class PatternsCheck(LinguisticCheck):
    def __init__(
        self,
        patterns: Union[List[str], List[Tuple[str, re.RegexFlag]]],
    ) -> None:
        # Originally I tried isinstance(patterns, Tuple[...]) for testing,
        # but that throws an exception because Tuple[...]
        # is only valid for type hinting :/
        if isinstance(patterns[0], Tuple):
            self.patterns = [
                re.compile(pattern, flags=flags) for pattern, flags in patterns
            ]
        else:
            self.patterns = [re.compile(pattern) for pattern in patterns]

    def execute(self, file_path: str, correction: str):
        return any(
            bool(pattern.search(correction)) for pattern in self.patterns
        )


class CompositeCheck(LinguisticCheck):
    def __init__(self, *checks: Iterable[LinguisticCheck]) -> None:
        self.checks = checks

    def execute(self, file_path: str, correction: str):
        return all(
            check.execute(file_path, correction) for check in self.checks
        )


class TextInFileCheck(CompositeCheck):
    def __init__(self, file: str, text: str) -> None:
        super().__init__(FileCheck(file), TextCheck(text))


class PatternInFileCheck(CompositeCheck):
    def __init__(
        self, file: str, pattern: str, flags: re.RegexFlag = 0
    ) -> None:
        super().__init__(FileCheck(file), PatternCheck(pattern, flags))


class PatternsInFileCheck(CompositeCheck):
    def __init__(
        self,
        file: str,
        patterns: Union[List[str], List[Tuple[str, re.RegexFlag]]],
    ) -> None:
        super().__init__(FileCheck(file), PatternsCheck(patterns))


class PatternInFilesCheck(CompositeCheck):
    def __init__(
        self, files: List[str], pattern: str, flags: re.RegexFlag = 0
    ) -> None:
        super().__init__(FilesCheck(files), PatternCheck(pattern, flags))


class PatternInFilePatternCheck(CompositeCheck):
    def __init__(
        self,
        file_pattern: str,
        text_pattern: str,
        file_pattern_flags: re.RegexFlag = 0,
        text_pattern_flags: re.RegexFlag = 0,
    ) -> None:
        super().__init__(
            FilePatternCheck(file_pattern, file_pattern_flags),
            PatternCheck(text_pattern, text_pattern_flags),
        )


class PatternsInFilePatternCheck(CompositeCheck):
    def __init__(
        self,
        file_pattern: str,
        patterns: Union[List[str], List[Tuple[str, re.RegexFlag]]],
        file_pattern_flags: re.RegexFlag = 0,
    ) -> None:
        super().__init__(
            FilePatternCheck(file_pattern, file_pattern_flags),
            PatternsCheck(patterns),
        )


def handle_linguistic_checks(
    file: str, correction: str, checks: Iterable[LinguisticCheck]
) -> bool:
    return any(check.execute(file, correction) for check in checks)
