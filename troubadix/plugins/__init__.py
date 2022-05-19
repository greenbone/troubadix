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

from typing import Iterable, List

from troubadix.plugin import Plugin

from .badwords import CheckBadwords
from .copyright_text import CheckCopyrightText
from .copyright_year import CheckCopyrightYear
from .creation_date import CheckCreationDate
from .cve_format import CheckCVEFormat
from .cvss_format import CheckCVSSFormat
from .dependencies import CheckDependencies
from .description import CheckDescription
from .double_end_points import CheckDoubleEndPoints
from .duplicate_oid import CheckDuplicateOID
from .duplicated_script_tags import CheckDuplicatedScriptTags
from .encoding import CheckEncoding
from .forking_nasl_functions import CheckForkingNaslFunctions
from .get_kb_on_services import CheckGetKBOnServices
from .grammar import CheckGrammar
from .http_links_in_tags import CheckHttpLinksInTags
from .illegal_characters import CheckIllegalCharacters
from .log_messages import CheckLogMessages
from .misplaced_compare_in_if import CheckMisplacedCompareInIf
from .missing_desc_exit import CheckMissingDescExit
from .missing_tag_solution import CheckMissingTagSolution
from .newlines import CheckNewlines
from .no_solution import CheckNoSolution
from .overlong_script_tags import CheckOverlongScriptTags
from .prod_svc_detect_in_vulnvt import CheckProdSvcDetectInVulnvt
from .reporting_consistency import CheckReportingConsistency
from .risk_factor import CheckRiskFactor
from .script_category import CheckScriptCategory
from .script_copyright import CheckScriptCopyright
from .script_family import CheckScriptFamily
from .script_version_and_last_modification_tags import (
    CheckScriptVersionAndLastModificationTags,
)
from .security_messages import CheckSecurityMessages
from .set_get_kb_calls import CheckWrongSetGetKBCalls
from .solution_text import CheckSolutionText
from .solution_type import CheckSolutionType
from .spelling import CheckSpelling
from .tabs import CheckTabs
from .todo_tbd import CheckTodoTbd
from .trailing_spaces_tabs import CheckTrailingSpacesTabs
from .update_modification_date import UpdateModificationDate
from .using_display import CheckUsingDisplay
from .valid_oid import CheckValidOID
from .valid_script_tag_names import CheckValidScriptTagNames
from .vt_placement import CheckVTPlacement

_PLUGINS = [
    CheckBadwords,
    CheckCVEFormat,
    CheckCVSSFormat,
    CheckCopyrightText,
    CheckCopyrightYear,
    CheckCreationDate,
    CheckDependencies,
    CheckDescription,
    CheckDoubleEndPoints,
    CheckDuplicatedScriptTags,
    CheckForkingNaslFunctions,
    CheckGetKBOnServices,
    CheckGrammar,
    CheckHttpLinksInTags,
    CheckIllegalCharacters,
    CheckLogMessages,
    CheckMisplacedCompareInIf,
    CheckMissingDescExit,
    CheckMissingTagSolution,
    CheckNewlines,
    CheckOverlongScriptTags,
    CheckProdSvcDetectInVulnvt,
    CheckReportingConsistency,
    CheckRiskFactor,
    CheckScriptCategory,
    CheckScriptCopyright,
    CheckScriptFamily,
    CheckScriptVersionAndLastModificationTags,
    CheckSecurityMessages,
    CheckSolutionText,
    CheckSolutionType,
    CheckSpelling,
    CheckTodoTbd,
    CheckTrailingSpacesTabs,
    CheckUsingDisplay,
    CheckVTPlacement,
    CheckValidOID,
    CheckValidScriptTagNames,
    CheckWrongSetGetKBCalls,
    CheckEncoding,
    CheckTabs,
]

_PRE_RUN_PLUGINS = [
    CheckDuplicateOID,
    CheckNoSolution,
]


class Plugins:
    def __init__(self, plugins: List[Plugin], prerun_plugins: List[Plugin]):
        self._plugins = plugins
        self._prerun_plugins = prerun_plugins

    def __len__(self) -> int:
        return len(self._plugins)

    def __iter__(self) -> Iterable[Plugin]:
        return iter(self._plugins)

    def get_prerun_plugins(self) -> Iterable[Plugin]:
        return self._prerun_plugins


class UpdatePlugins(Plugins):
    def __init__(self):
        super().__init__([UpdateModificationDate], [])


class StandardPlugins(Plugins):
    def __init__(
        self,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
    ) -> None:
        super().__init__(_PLUGINS, _PRE_RUN_PLUGINS)

        if excluded_plugins:
            self._plugins = [
                plugin
                for plugin in self._plugins
                if plugin.__name__ not in excluded_plugins
                and plugin.name not in excluded_plugins
            ]
            self._prerun_plugins = [
                plugin
                for plugin in self._prerun_plugins
                if plugin.__name__ not in excluded_plugins
                and plugin.name not in excluded_plugins
            ]
        if included_plugins:
            self._plugins = [
                plugin
                for plugin in self._plugins
                if plugin.__name__ in included_plugins
                or plugin.name in included_plugins
            ]
            self._prerun_plugins = [
                plugin
                for plugin in self._prerun_plugins
                if plugin.__name__ in included_plugins
                or plugin.name in included_plugins
            ]
