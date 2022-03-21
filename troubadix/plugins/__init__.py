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
from .forking_nasl_funcs import CheckForkingNaslFuncs
from .get_kb_on_services import CheckGetKBOnServices
from .grammar import CheckGrammar
from .http_links_in_tags import CheckHttpLinksInTags
from .includes import CheckIncludes
from .log_messages import CheckLogMessages
from .misplaced_compare_in_if import CheckMisplacedCompareInIf
from .missing_desc_exit import CheckMissingDescExit
from .missing_tag_solution import CheckMissingTagSolution
from .newlines import CheckNewlines
from .openvas_lint import CheckOpenvasLint
from .overlong_script_tags import CheckOverlongScriptTags
from .prod_svc_detect_in_vulnvt import CheckProdSvcDetectInVulnvt
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
from .updated_date_version import CheckUpdatedDateVersion
from .using_display import CheckUsingDisplay
from .valid_oid import CheckValidOID
from .valid_script_tag_names import CheckValidScriptTagNames
from .vt_placement import CheckVTPlacement

_NASL_ONLY_PLUGINS = [
    CheckBadwords,
    CheckCVEFormat,
    CheckCVSSFormat,
    CheckCopyrightText,
    CheckCopyrightYear,
    CheckCreationDate,
    CheckDependencies,
    CheckDescription,
    CheckDoubleEndPoints,
    CheckDuplicateOID,
    CheckDuplicatedScriptTags,
    CheckForkingNaslFuncs,
    CheckGetKBOnServices,
    CheckGrammar,
    CheckHttpLinksInTags,
    CheckIncludes,
    CheckLogMessages,
    CheckMisplacedCompareInIf,
    CheckMissingDescExit,
    CheckMissingTagSolution,
    CheckNewlines,
    CheckOpenvasLint,
    CheckOverlongScriptTags,
    CheckProdSvcDetectInVulnvt,
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
    CheckUpdatedDateVersion,
    CheckUsingDisplay,
    CheckVTPlacement,
    CheckValidOID,
    CheckValidScriptTagNames,
    CheckWrongSetGetKBCalls,
    UpdateModificationDate,
]

_PLUGINS = [
    CheckEncoding,
    CheckTabs,
]


class Plugins:
    def __init__(
        self,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
    ) -> None:
        self.plugins = _NASL_ONLY_PLUGINS
        if excluded_plugins:
            self.plugins = [
                plugin
                for plugin in _NASL_ONLY_PLUGINS
                if plugin.__name__ not in excluded_plugins
            ]
        if included_plugins:
            self.plugins = [
                plugin
                for plugin in _NASL_ONLY_PLUGINS
                if plugin.__name__ in included_plugins
            ]

    def __iter__(self) -> Iterable[Plugin]:
        return iter(self.plugins)
